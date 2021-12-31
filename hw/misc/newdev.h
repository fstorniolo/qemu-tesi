#ifndef NEWDEV_H
#define NEWDEV_H
#endif

#include "hw/pci/pci.h"

#define TYPE_NEWDEV_DEVICE "newdev"
#define NEWDEV(obj)        OBJECT_CHECK(NewdevState, obj, TYPE_NEWDEV_DEVICE)

#define NEWDEV_REG_PCI_BAR      0
#define NEWDEV_BUF_PCI_BAR      1
#define NEWDEV_REG_END          92
#define NEWDEV_REG_MASK         0xff
#define NEWDEV_BUF_MASK         0xffff
#define NEWDEV_BUF_SIZE         65536


//not used, misleading. OLD used only in ioregs R/W
#define NEWDEV_REG_STATUS_IRQ   0
#define NEWDEV_REG_RAISE_IRQ    8
#define NEWDEV_REG_LOWER_IRQ    12

// DEVICE BUFMMIO STRUCTURE. OFFSET IN #bytes/sizeof(uint32_t)

// +---+--------------------------------+
// | 0 | irq_status [R] / raise_irq [W] |
// +---+--------------------------------+
// | 1 |          lower_irq [W]         |
// +---+--------------------------------+
// | 2 |      unspecified/reserved      |
// +---+--------------------------------+
// | 3 |      unspecified/reserved      |
// +---+--------------------------------+
// | 4 |                                |
// +---+                                |
// | 5 |            buffer              |
// +---+                                |
// |   |                                |
// |   |                                |
//                  ......
// |   |                                |
// |   |                                |
// +---+--------------------------------+

typedef struct NewdevTranslateEntry {
    uint64_t gpa_start;
    uint64_t gpa_end;
    uint64_t size;
    void *hva_start;
    MemoryRegion *mr;
} NewdevTranslateEntry;

typedef struct {
    PCIDevice pdev;
    MemoryRegion regs;
    MemoryRegion mmio;

    // Used for address translation
    MemoryListener memory_listener;
    NewdevTranslateEntry *trans_entries;
    unsigned int num_trans_entries;
    NewdevTranslateEntry *trans_entries_tmp;
    unsigned int num_trans_entries_tmp;

    /* Storage for the I/O registers. */
    uint32_t ioregs[NEWDEV_REG_END >> 2];

    /* Storage for the buffer. */
    uint32_t *buf;

    QemuThread thread;

    QemuMutex thr_mutex;
    QemuCond thr_cond;

    QemuMutex thr_mutex_migration;
    QemuCond thr_cond_migration;

    bool stopping;
    bool ready_to_migration;
    uint32_t irq_status;


    bool hyperthreading_remapping; 
    
    int listen_fd;  //listening socket fd
    int connect_fd; //connected socket fd (use for command exchange)

} NewdevState;

NewdevState *get_newdev_state(void);
bool get_ready_to_migration(void);