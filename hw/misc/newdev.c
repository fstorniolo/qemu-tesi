/*
 * QEMU extensible paravirtualization device
 * 2020 Giacomo Pellicci
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "hw/pci/pci.h"
#include "hw/hw.h"
#include "hw/pci/msi.h"
#include "qemu/timer.h"
#include "qemu/main-loop.h" /* iothread mutex */
#include "qemu/module.h"
#include "qapi/visitor.h"
#include "qemu/range.h"

#include <sys/inotify.h>
#include <errno.h>
#include <poll.h>

#include <sys/types.h> 
#include <sys/socket.h> 

#include "hw/misc/bpf_injection_msg.h"
#include "hw/misc/newdev.h"
#include "hw/core/cpu.h"
#include "accel/kvm/translate-gpa_2_hva.h"

// Maffione includes
#include "qemu/osdep.h"
#include "hw/hw.h"
#include "hw/pci/pci.h"
#include "hw/pci/msi.h"
#include "hw/pci/msix.h"
#include "net/net.h"
#include "sysemu/sysemu.h"
#include "sysemu/kvm.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "qemu/iov.h"
#include "qemu/range.h"
#include "qapi/error.h"
#include "linux/virtio_net.h"

//Affinity part
#include <sys/sysinfo.h>
#define MAX_CPU 64
#define SET_SIZE CPU_ALLOC_SIZE(64)
#define NEWDEV_DEVICE_ID 0x11ea
#define BPF_INSN_SIZE   8


/* Debug information. Define it as 1 get for basic debugging,
 * and as 2 to get additional (verbose) memory listener logs. */
#define NEWDEV_DEBUG 1

#if NEWDEV_DEBUG > 0
#define DBG(fmt, ...) do { \
        fprintf(stderr, "newdev-pci: " fmt "\n", ## __VA_ARGS__); \
    } while (0)
#else
#define DBG(fmt, ...) do {} while (0)
#endif

#if NEWDEV_DEBUG > 1
#define DBG_V(fmt, ...) do { \
        fprintf(stderr, "newdev-pci: " fmt "\n", ## __VA_ARGS__); \
    } while (0)
#else
#define DBG_V(fmt, ...) do {} while (0)
#endif

static const char *regnames[] = {
    "STATUS",
    "CTRL",
    "RAISE_IRQ",
    "LOWER_IRQ",
};

static NewdevState *newdev_p;
static void newdev_raise_irq(NewdevState *newdev, uint32_t val);
static void connected_handle_read(void *opaque);
// static int newdev_progs_load(NewdevState *s /*const char *progsname, */);


struct bpf_injection_msg_t prepare_bpf_injection_message(const char* path){
    struct bpf_injection_msg_t mymsg;
    int len;
    mymsg.header.version = DEFAULT_VERSION;
    mymsg.header.type = PROGRAM_INJECTION;
    FILE* fp = fopen(path, "r");
    if(fp) {
        fseek(fp, 0 , SEEK_END);
        mymsg.header.payload_len = ftell(fp);     
        fseek(fp, 0 , SEEK_SET);// needed for next read from beginning of file
        mymsg.payload = malloc(mymsg.header.payload_len);
        len = fread(mymsg.payload, 1, mymsg.header.payload_len, fp);
        // printf("readlen %d\n", len);
        if(len != mymsg.header.payload_len) {
            // printf("Error preparing the message\n");
            mymsg.header.type = ERROR;
            fclose(fp);
            free(mymsg.payload);
            return mymsg;
        }
      fclose(fp);
    }
    return mymsg;
}

void print_bpf_injection_message(struct bpf_injection_msg_header myheader){
    printf("  Version:%u\n  Type:%u\n  Payload_len:%u\n", myheader.version, myheader.type, myheader.payload_len);
}


static void accept_handle_read(void *opaque){
    NewdevState *newdev = opaque;

    DBG("accept_handle_read\n");
    DBG("incoming connection on socket fd:\t%d\n", newdev->listen_fd);

    //Accept connection from peer
    newdev->connect_fd = accept(newdev->listen_fd, NULL, NULL);
    DBG("accepted connection from peer. connect_fd:\t%d\n", newdev->connect_fd);

    //Add connect_fd from list of watched fd in iothread select
    qemu_set_fd_handler(newdev->connect_fd, connected_handle_read, NULL, newdev);


    //Remove listen_fd from watched fd in iothread select
    qemu_set_fd_handler(newdev->listen_fd, NULL, NULL, NULL);

    //don't close listen_fd socket... useful for later reconnection ?
    //qemu_close(newdev->listen_fd);
    return;
}

static void connected_handle_read(void *opaque){
    NewdevState *newdev = opaque;
    int len = 0;
    struct bpf_injection_msg_header* myheader;


    DBG("connect_handle_read\n");
    DBG("readable socket fd:\t%d\n", newdev->connect_fd);

    // Receive message header (version|type|payload_length) [place it in newdev->buf at offset 4*sizeof(uint32_t)]
    len = recv(newdev->connect_fd, newdev->buf + 4, sizeof(struct bpf_injection_msg_header), 0);
    if(len <= 0){
        DBG("len = %d [<=0] --> connection reset or error. Removing connect_fd, restoring listen_fd\n", len);
        //connection closed[0] or error[<0]

        //Remove connect_fd from watched fd in iothread select
        qemu_set_fd_handler(newdev->connect_fd, NULL, NULL, NULL);
        newdev->connect_fd = -1;

        //Add listen_fd from list of watched fd in iothread select
        qemu_set_fd_handler(newdev->listen_fd, accept_handle_read, NULL, newdev);  
        return;
    }
    myheader = (struct bpf_injection_msg_header*) newdev->buf + 4;
    print_bpf_injection_message(*myheader);   

    // Receive message payload. Place it in newdev->buf + 4 + sizeof(struct bpf_injection_msg_header)/sizeof(uint32_t)
    // All those manipulation is because newdev->buf is a pointer to uint32_t so you have to provide offset in bytes/4 or in uint32_t
    len = recv(newdev->connect_fd, newdev->buf + 4 + sizeof(struct bpf_injection_msg_header)/sizeof(uint32_t), myheader->payload_len, 0);

    switch(myheader->type){
        case PROGRAM_INJECTION:
            // Program is stored in buf. Trigger interrupt to propagate this info
            // to the guest side. Convention::: use interrupt number equal to case
            DBG("PROGRAM_INJECTION-> interrupt fired");
            DBG("Payload size: %d", myheader->payload_len);
            // newdev_progs_load(newdev);
            newdev_raise_irq(newdev, PROGRAM_INJECTION);
            break;

        case FIRST_ROUND_MIGRATION:
            {
                DBG("FIRST_ROUND_MIGRATION \n");
                
                qemu_mutex_lock(&newdev->thr_mutex_migration);
                newdev->ready_to_migration = true;
                qemu_mutex_unlock(&newdev->thr_mutex_migration);

                DBG("Payload: %d",*(int*) (newdev->buf + 4 + sizeof(struct bpf_injection_msg_header)/sizeof(uint32_t)));

                break;
            }
        default:
            //unexpected value is threated like an error 
            return;            
    }
    return;
}


static void newdev_raise_irq(NewdevState *newdev, uint32_t val){
    newdev->irq_status |= val;
    DBG("raise irq\tirq_status=%x", newdev->irq_status);
    if (newdev->irq_status) {
        DBG("raise irq\tinside if");
        pci_set_irq(&newdev->pdev, 1);        
    }
}

static void newdev_lower_irq(NewdevState *newdev, uint32_t val){
    newdev->irq_status &= ~val;
    DBG("lower irq\tirq_status=%x", newdev->irq_status);
    if (!newdev->irq_status) {
        DBG("lower irq\tinside if");
        pci_set_irq(&newdev->pdev, 0);
    }
}

static uint64_t newdev_io_read(void *opaque, hwaddr addr, unsigned size){
    NewdevState *newdev = opaque;
    uint64_t val;
    unsigned int index;

    addr = addr & NEWDEV_REG_MASK;
    index = addr >> 2;

    if (addr >= NEWDEV_REG_END) {
        DBG("Unknown I/O read, addr=0x%08"PRIx64, addr);
        return 0;
    }

    switch(addr){
        case NEWDEV_REG_STATUS_IRQ:
            val = newdev->irq_status;
            break;
        default:
            val = newdev->ioregs[index];
            break;            
    }

    DBG("I/O read from %s, val=0x%08" PRIx64, regnames[index], val);

    return val;
}

static void newdev_io_write(void *opaque, hwaddr addr, uint64_t val, unsigned size){
    NewdevState *newdev = opaque;
    unsigned int index;

    addr = addr & NEWDEV_REG_MASK;
    index = addr >> 2;

    if (addr >= NEWDEV_REG_END) {
        DBG("Unknown I/O write, addr=0x%08"PRIx64", val=0x%08"PRIx64,
            addr, val);
        return;
    }

    assert(index < ARRAY_SIZE(regnames));

    DBG("I/O write to %s, val=0x%08" PRIx64, regnames[index], val);

    switch(addr){
        case NEWDEV_REG_RAISE_IRQ:
            newdev_raise_irq(newdev, val);
            //TO DO Serve il break?
            break;
        case NEWDEV_REG_LOWER_IRQ:
            newdev_lower_irq(newdev, val);
            break;
        default:            
            newdev->ioregs[index] = val;
            break;
    }

}

static uint64_t newdev_bufmmio_read(void *opaque, hwaddr addr, unsigned size){
    NewdevState *newdev = opaque;
    unsigned int index;

    addr = addr & NEWDEV_BUF_MASK;
    index = addr >> 2;

    if (addr + size > NEWDEV_BUF_SIZE * sizeof(uint32_t)) {
        DBG("Out of bounds BUF read, addr=0x%08"PRIx64, addr);
        return 0;
    }

    switch(index){
        case 0:
            DBG("BUF read [case 0] val=0x%08" PRIx32, newdev->irq_status);
            return newdev->irq_status;
        default:
            break;
    }

    return newdev->buf[index];
}

static void newdev_bufmmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned size){
    NewdevState *newdev = opaque;
    unsigned int index;

    addr = addr & NEWDEV_BUF_MASK;
    index = addr >> 2;

    DBG_V("INSIDE BUFMMIO WRITE");
    DBG_V("Addr: %ld, Index: %d", addr, index);

    if (addr + size > NEWDEV_BUF_SIZE * sizeof(uint32_t)) {
        DBG("Out of bounds BUF write, addr=0x%08"PRIx64, addr);
        return;
    }

    // DBG("BUF write val=0x%08" PRIx64, val);

    switch(index){
        case 0:
            newdev_raise_irq(newdev, val);
            break;
        case 1:        
            newdev_lower_irq(newdev, val);
            break;
        case 2:
            //doorbell region for guest->hw notification
            DBG("doorbell in device!");

            struct bpf_injection_msg_header* myheader;
            myheader = (struct bpf_injection_msg_header*) newdev->buf + 4;
            DBG("version: %d type: %d payload-len: %d", myheader->version, myheader->type, myheader->payload_len);
            
            switch(myheader->type){
                case FIRST_ROUND_MIGRATION:
                    if(myheader->payload_len % 3 != 0){
                        DBG("Unexpected payload len in FIRST_ROUND_MIGRATION");
                        break;
                    }

                    // Get gpa buffer 
                    unsigned long high_addr_buff, low_addr_buff;
                    high_addr_buff = *(newdev->buf + 5 + (myheader->payload_len / 4));
                    low_addr_buff = *(newdev->buf + 5 +(myheader->payload_len / 4) + 1);
                    hwaddr address_buffer = (high_addr_buff << 32) + low_addr_buff;



                    DBG("GPA HighAddress: %lx \n", high_addr_buff);
                    DBG("GPA LowAddress: %lx \n", low_addr_buff);

                    DBG("GPA Address: %lx \n", address_buffer);

                    unsigned long high_addr, low_addr, order;

                    void* hva_address_buffer;
                    for(int i = 0; i < myheader->payload_len / 12; i++){
                        
                        high_addr = *(newdev->buf + 5 + i * 3);
                        low_addr = *(newdev->buf + 5 + i * 3 + 1);
                        order = *(newdev->buf + 5 + i * 3 + 2);
                        hwaddr free_page_addr = (high_addr << 32) + low_addr + order - order;

                        DBG_V("Address: %lx Order: %lu", free_page_addr, order);
                        void* hva = translate_gpa_2_hva(free_page_addr);
                        if(hva != NULL)
                            DBG_V("Address translated: %p", hva);


                        hva_address_buffer = translate_gpa_2_hva(address_buffer);
                        unsigned long *tmp = hva_address_buffer;
                        hwaddr new_phys_page = *tmp;
                        address_buffer += 8;

                        hva_address_buffer = translate_gpa_2_hva(address_buffer);
                        tmp = hva_address_buffer;
                        hwaddr new_order  = *tmp;
                        address_buffer += 8;

                        if(new_order != order || new_phys_page != free_page_addr)
                            DBG("Diversi \n");
                    }

                    
                    qemu_mutex_lock(&newdev->thr_mutex_migration);
                    newdev->ready_to_migration = true;
                    qemu_cond_signal(&newdev->thr_cond_migration);
                    qemu_mutex_unlock(&newdev->thr_mutex_migration);

                    // Waiting for the end of setup migration to communicate to the guest driver setup migration phase is ended

                    DBG("Waiting for end of  setup migration phase \n");

                    qemu_mutex_lock(&newdev->thr_mutex_end_1st_round_migration);

                    while (!newdev->end_1st_round_migration)
                        qemu_cond_wait(&newdev->thr_cond_end_1st_round_migration, &newdev->thr_mutex_end_1st_round_migration);

                    qemu_mutex_unlock(&newdev->thr_mutex_end_1st_round_migration);
                    DBG("Setup phase migration is ended \n");
                    
                    break;

                default:
                    DBG("Default case");
                    break;
            }

            //reset doorbell
            newdev->buf[index] = 0;
            break;
        case 3:
            break;
        default:
            DBG_V("WRITING IN THE BUFFER: %lu AT INDEX: %d" , val, index);
            newdev->buf[index] = val;
            break;
    }
    return;
}

static uint64_t
newdev_progmmio_read(void *opaque, hwaddr addr, unsigned size)
{
    NewdevState *newdev = opaque;
    uint32_t *readp;

    DBG("Inside progmmio read");

    if (addr + size > newdev->prog->num_insns * BPF_INSN_SIZE) {
        DBG("Out of bounds prog I/O read, addr=0x%08"PRIx64, addr);
        return 0;
    }

    readp = (uint32_t *)(((uint8_t *)newdev->prog->insns) + addr);

    return *readp;
}


static const MemoryRegionOps newdev_io_ops = {
    .read = newdev_io_read,
    .write = newdev_io_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },

};

static const MemoryRegionOps newdev_bufmmio_ops = {
    .read = newdev_bufmmio_read,
    .write = newdev_bufmmio_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },

};

static const MemoryRegionOps newdev_progmmio_ops = {
    .read = newdev_progmmio_read,
    .write = NULL, /* this is a read-only region */
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
    /* These are only limitations of the emulation code, and they are not
     * visible to the guest, which can still perform larger or shorter
     * writes. See description of 'impl' and 'valid' fields. */
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

NewdevState *get_newdev_state(void){
    assert(newdev_p);
    return newdev_p;
}

bool get_ready_to_migration(void){
    NewdevState* new_dev_state = get_newdev_state();
    return new_dev_state->ready_to_migration;
}

void setup_migration_phase_start(void)
{
    DBG("SETUP MIGRATION PHASE START \n");
    newdev_raise_irq(newdev_p, FIRST_ROUND_MIGRATION_START); 
}


void setup_migration_phase_ended(void)
{
    // Comunicate to the guest driver setup migration phase is ended
    DBG("SETUP MIGRATION PHASE ENDED \n");
    newdev_raise_irq(newdev_p, FIRST_ROUND_MIGRATION_ENDED);

}

static int make_socket (uint16_t port){
  int sock;
  struct sockaddr_in name;

  /* Create the socket. */
  sock = socket (PF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    {
      perror ("socket");
      return -1;
    }

  /* Give the socket a name. */
  name.sin_family = AF_INET;
  name.sin_port = htons (port);
  name.sin_addr.s_addr = htonl (INADDR_ANY);
  if (bind (sock, (struct sockaddr *) &name, sizeof (name)) < 0)
    {
      perror ("bind");
      return -1;
    }

  return sock;
}

static void
newdev_memli_begin(MemoryListener *listener)
{
    // DBG("Inside newdev_memli_begin");
    NewdevState *s = container_of(listener, NewdevState, memory_listener);

    s->num_trans_entries_tmp = 0;
    s->trans_entries_tmp = NULL;
}

static void
newdev_memli_region_add(MemoryListener *listener,
                       MemoryRegionSection *section)
{
    // DBG("Inside newdev_memli_region_add");
    NewdevState *s = container_of(listener, NewdevState, memory_listener);
    uint64_t size = int128_get64(section->size);
    uint64_t gpa_start = section->offset_within_address_space;
    uint64_t gpa_end = range_get_last(gpa_start, size) + 1;
    void *hva_start;
    NewdevTranslateEntry *last = NULL;
    bool add_entry = true;

    if (!memory_region_is_ram(section->mr)) {
        return;
    }

    hva_start = memory_region_get_ram_ptr(section->mr) +
                      section->offset_within_region;
    DBG_V("new memory section %lx-%lx sz %lx %p", gpa_start, gpa_end,
        size, hva_start);
    if (s->num_trans_entries_tmp > 0) {
        /* Check if we can coalasce the last MemoryRegionSection to
         * the current one. */
        last = s->trans_entries_tmp + s->num_trans_entries_tmp - 1;
        if (gpa_start == last->gpa_end &&
            hva_start == last->hva_start + last->size) {
            add_entry = false;
            last->gpa_end = gpa_end;
            last->size += size;
        }
    }

    if (add_entry) {
        s->num_trans_entries_tmp++;
        s->trans_entries_tmp = g_renew(NewdevTranslateEntry,
            s->trans_entries_tmp, s->num_trans_entries_tmp);
        last = s->trans_entries_tmp + s->num_trans_entries_tmp - 1;
        last->gpa_start = gpa_start;
        last->gpa_end = gpa_end;
        last->size = size;
        last->hva_start = hva_start;
        last->mr = section->mr;
        memory_region_ref(last->mr);
    }
}

static void
newdev_memli_commit(MemoryListener *listener)
{
    // DBG("Inside newdev_memli_commit");
    NewdevState *s = container_of(listener, NewdevState, memory_listener);
    NewdevTranslateEntry *old_trans_entries;
    int num_old_trans_entries;
    int i;

    old_trans_entries = s->trans_entries;
    num_old_trans_entries = s->num_trans_entries;
    s->trans_entries = s->trans_entries_tmp;
    s->num_trans_entries = s->num_trans_entries_tmp;

#if NEWDEV_DEBUG > 1
    for (i = 0; i < s->num_trans_entries; i++) {
        NewdevTranslateEntry *te = s->trans_entries + i;
        DBG_V("    entry %d: gpa %lx-%lx size %lx hva_start %p", i,
            te->gpa_start, te->gpa_end, te->size, te->hva_start);
    }
#endif

    s->trans_entries_tmp = NULL;
    s->num_trans_entries_tmp = 0;
    for (i = 0; i < num_old_trans_entries; i++) {
        NewdevTranslateEntry *te = old_trans_entries + i;
        memory_region_unref(te->mr);
    }
    g_free(old_trans_entries);
}

void* newdev_translate_addr(NewdevState *s, uint64_t gpa, uint64_t len)
{
    DBG_V("Inside newdev_translate_addr");
    NewdevTranslateEntry *te = s->trans_entries + 0;

    if (unlikely(!(te->gpa_start <= gpa && gpa + len <= te->gpa_end))) {
        int i;

        for (i = 1; i < s->num_trans_entries; i++) {
            te = s->trans_entries + i;
            if (te->gpa_start <= gpa && gpa + len <= te->gpa_end) {
                /* Match. Move this entry to the first position. */
                NewdevTranslateEntry tmp = *te;
                *te = s->trans_entries[0];
                s->trans_entries[0] = tmp;
                te = s->trans_entries + 0;
                break;
            }
        }
        assert(i < s->num_trans_entries);
    }

    return te->hva_start + (gpa - te->gpa_start);
}

/*
static char *
bpfhv_progpath(const char *progsname)
{
    //char filename[64];

    //snprintf(filename, sizeof(filename), "%s_progs.o", progsname);

    return qemu_find_file(2, progsname);
}
*/

#if 0

static int
newdev_progs_load_fd(NewdevState *s, int fd, const char *path)
{
    const char *prog_names[1] = {"test"};
    GElf_Ehdr ehdr;
    int ret = -1;
    Elf *elf;
    int i;

    for (i = 0; i < BPFHV_PROG_MAX; i++) {
        if (s->prog->insns != NULL) {
            g_free(s->prog->insns);
            s->prog->insns = NULL;
        }
        s->prog->num_insns = 0;
    }

    if (elf_version(EV_CURRENT) == EV_NONE) {
        DBG("ELF version mismatch \n");
        return -1;
    }
    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        DBG("Failed to initialize ELF library for %s", path);
        return -1;
    }

    if (gelf_getehdr(elf, &ehdr) != &ehdr) {
        DBG("Failed to get ELF header for %s", path);
        goto err;
    }

    for (i = 1; i < ehdr.e_shnum; i++) {
        Elf_Data *sdata;
        GElf_Shdr shdr;
        Elf_Scn *scn;
        char *shname;

        scn = elf_getscn(elf, i);
        if (!scn) {
            continue;
        }

        if (gelf_getshdr(scn, &shdr) != &shdr) {
            continue;
        }

        if (shdr.sh_type != SHT_PROGBITS) {
            continue;
        }

        shname = elf_strptr(elf, ehdr.e_shstrndx, shdr.sh_name);
        if (!shname || shdr.sh_size == 0) {
            continue;
        }

        sdata = elf_getdata(scn, NULL);
        if (!sdata || elf_getdata(scn, sdata) != NULL) {
            continue;
        }

        {
            int j;

            for (j = 0; j < ARRAY_SIZE(prog_names); j++) {
                if (!strcmp(shname, prog_names[j])) {
                    break;
                }
            }

            if (j >= ARRAY_SIZE(prog_names)) {
                continue;
            }

            if (s->prog->insns != NULL) {
                DBG("warning: %s contains more sections with name %s",
                    path, prog_names[j]);
                continue;
            }

            s->prog->insns = g_malloc(sdata->d_size);
            memcpy(s->prog->insns, sdata->d_buf, sdata->d_size);
            s->prog->num_insns = sdata->d_size / BPF_INSN_SIZE;
        }
    }

    ret = 0;
    // pstrcpy(s->progsname, sizeof(s->progsname), progsname);
    // DBG("Loaded program: %s", s->progsname);
err:
    elf_end(elf);

    return ret;
} 


static int
newdev_progs_load(NewdevState *s /*const char *progsname, */)
{
    int ret = -1;
    //char *path;
    int fd;

    /*if (!strncmp(progsname, s->progsname, sizeof(s->progsname))) {
        return 0;
    }

    path = bpfhv_progpath(progsname);
    if (!path) {
        error_setg(errp, "Could not locate bpfhv_%s_progs.o", progsname);
        return -1;
    }*/

    // const char *prog_name = "test_bpf_prog.o";

    /*path = bpfhv_progpath(prog_name);
    if (!path) {
        //error_setg(errp, "Could not locate test_bpf_prog.o", progsname);
        DBG("Could not locate test_bpf_prog.o \n");
        return -1;
    } */

    char path[] = "/home/filippo/Desktop/Tesi/eBPF-injection/shared/guest_programs/test_bpf_prog.o";

    fd = open(path, O_RDONLY, 0);
    if (fd < 0) {
        DBG("Failed to open %s", path);

        // error_setg_errno(errp, errno, "Failed to open %s", path);
    }

    DBG("path: %s aperto \n", path);

    ret = newdev_progs_load_fd(s, fd, path);
    close(fd);

    return ret;
}
#endif

static void newdev_realize(PCIDevice *pdev, Error **errp)
{
    NewdevState *newdev = NEWDEV(pdev);
    uint8_t *pci_conf = pdev->config;

    pci_config_set_interrupt_pin(pci_conf, 1);

    if (msi_init(pdev, 0, 1, true, false, errp)) {
        return;
    }

    qemu_mutex_init(&newdev->thr_mutex);
    qemu_cond_init(&newdev->thr_cond);

    qemu_mutex_init(&newdev->thr_mutex_migration);
    qemu_cond_init(&newdev->thr_cond_migration);

    qemu_mutex_init(&newdev->thr_mutex_end_1st_round_migration);
    qemu_cond_init(&newdev->thr_cond_end_1st_round_migration);

    /* Init I/O mapped memory region, exposing newdev registers. */
    memory_region_init_io(&newdev->regs, OBJECT(newdev), &newdev_io_ops, newdev,
                    "newdev-regs", NEWDEV_REG_MASK + 1);
    pci_register_bar(pdev, NEWDEV_REG_PCI_BAR, PCI_BASE_ADDRESS_SPACE_MEMORY, &newdev->regs);

    /* Init memory mapped memory region, to expose eBPF programs. */
    memory_region_init_io(&newdev->mmio, OBJECT(newdev), &newdev_bufmmio_ops, newdev,
                    "newdev-buf", NEWDEV_BUF_SIZE * sizeof(uint32_t));
    pci_register_bar(pdev, NEWDEV_BUF_PCI_BAR, PCI_BASE_ADDRESS_SPACE_MEMORY, &newdev->mmio);
    
    /* Init memory mapped memory region, to expose eBPF programs. */
    // TO DO: refactor this code
    memory_region_init_io(&newdev->progmmio, OBJECT(newdev), &newdev_progmmio_ops, newdev,
                          "newdev-prog", NEWDEV_BUF_SIZE * sizeof(uint32_t));
    pci_register_bar(pdev, NEWDEV_PROG_PCI_BAR,
                     PCI_BASE_ADDRESS_SPACE_MEMORY, &newdev->progmmio);


    newdev->buf = malloc(NEWDEV_BUF_SIZE * sizeof(uint32_t));
    

    //set_fd_handler?
    newdev->listen_fd = -1;
    newdev->connect_fd = -1;

    //setup ht (default=disabled)
    newdev->hyperthreading_remapping = false;

    newdev->listen_fd = make_socket(9999);
    if (newdev->listen_fd < 0){
        return;
    } 

    DBG("socket fd:\t%d", newdev->listen_fd);

    if (listen (newdev->listen_fd, 1) < 0){
      DBG("listen error\n");
      return;        
    }
    DBG("listen\n");

    qemu_set_fd_handler(newdev->listen_fd, accept_handle_read, NULL, newdev);        

    // Configure memory listener
    newdev->memory_listener.priority = 10,
    newdev->memory_listener.begin = newdev_memli_begin,
    newdev->memory_listener.commit = newdev_memli_commit,
    newdev->memory_listener.region_add = newdev_memli_region_add,
    newdev->memory_listener.region_nop = newdev_memli_region_add,
    memory_listener_register(&newdev->memory_listener, &address_space_memory);
    
    newdev->ready_to_migration = false;
    newdev->end_1st_round_migration = false;
    DBG("qemu listen_fd added");


    DBG("**** device realized ****");

}

static void newdev_uninit(PCIDevice *pdev)
{
    NewdevState *newdev = NEWDEV(pdev);

    qemu_mutex_lock(&newdev->thr_mutex);
    newdev->stopping = true;
    qemu_mutex_unlock(&newdev->thr_mutex);
    qemu_cond_signal(&newdev->thr_cond);
    qemu_thread_join(&newdev->thread);

    qemu_cond_destroy(&newdev->thr_cond);
    qemu_mutex_destroy(&newdev->thr_mutex);

    qemu_cond_destroy(&newdev->thr_cond_migration);
    qemu_mutex_destroy(&newdev->thr_mutex_migration);

    qemu_cond_destroy(&newdev->thr_cond_end_1st_round_migration);
    qemu_mutex_destroy(&newdev->thr_mutex_end_1st_round_migration);

    msi_uninit(pdev);


    //unset_fd_handler
    if (newdev->listen_fd != -1) {
        qemu_set_fd_handler(newdev->listen_fd, NULL, NULL, NULL);
        qemu_close(newdev->listen_fd);
    }

    DBG("**** device unrealized ****");
}


static void newdev_class_init(ObjectClass *class, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(class);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(class);

    k->realize = newdev_realize;
    k->exit = newdev_uninit;
    k->vendor_id = PCI_VENDOR_ID_QEMU;
    k->device_id = NEWDEV_DEVICE_ID;
    
    k->class_id = PCI_CLASS_OTHERS;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static void newdev_instance_init(Object *obj){    
    newdev_p = NEWDEV(obj);
    return;
}

static void newdev_register_types(void)
{
    static InterfaceInfo interfaces[] = {
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { },
    };
    static const TypeInfo newdev_info = {
        .name          = TYPE_NEWDEV_DEVICE,
        .parent        = TYPE_PCI_DEVICE,
        .instance_size = sizeof(NewdevState),
        .instance_init = newdev_instance_init,
        .class_init    = newdev_class_init,
        .interfaces = interfaces,
    };

    type_register_static(&newdev_info);
}
type_init(newdev_register_types)
