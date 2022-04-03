/*
 * BPF message injection library
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

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

//cut

/*
*
*	Message structure used to exchange information between guest
*	and host during setup and execution phase of given eBPF programs.
*	Typical workflow is to have the host sending a message containing 
*	the eBPF program to be executed and then receive from guest a result
*	to be used in the specific scenario.
*
*/

/* type defines */
#define PROGRAM_INJECTION 							1
#define PROGRAM_INJECTION_RESULT 					2
#define PROGRAM_MEMORY_INFO                         3
#define PROGRAM_SET_MAXIMUM_ORDER                   4
#define ENABLE_MIGRATION_SETUP_OPTIMIZATION         10
#define DISABLE_MIGRATION_SETUP_OPTIMIZATION        11
#define FIRST_ROUND_MIGRATION						20
#define FIRST_ROUND_MIGRATION_ENDED                 21
#define FIRST_ROUND_MIGRATION_START                 5
/* version defines */
#define DEFAULT_VERSION 							1

// +----+---------+------+----------------+
// | 0  | version | type | payload length |
// +----+---------+------+----------------+
// | 32 |                                 |
// +----+             payload             |
// | 64 |                                 |
// +----+---------------------------------+

struct bpf_injection_msg_header;
struct bpf_injection_msg_t;
void print_bpf_injection_message(struct bpf_injection_msg_header myheader);

struct bpf_injection_msg_header {
	uint8_t version;		//version of the protocol
	uint8_t type;			//what kind of payload is carried
	uint16_t payload_len;	//payload length
};

struct bpf_injection_msg_t {
	struct bpf_injection_msg_header header;
	void* payload;
};

struct cpu_affinity_infos_t {
	uint16_t n_pCPU;
	uint16_t n_vCPU;
	//bool* pin;	//unnecessary in message
};

//cut

