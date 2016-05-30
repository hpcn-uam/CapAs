#ifndef _HPCAP_IXGBE_H_
#define _HPCAP_IXGBE_H_

#include <linux/cdev.h>

#include "../../include/hpcap.h"
#if defined(HPCAP_IXGBE)
	#include "../hpcap_ixgbe-3.7.17_buffer/driver/ixgbe.h"
#elif defined(HPCAP_IXGBEVF)
	#include "../hpcap_ixgbevf-2.14.2/driver/ixgbevf.h"
#endif

#if ( defined(HPCAP_IXGBE) || defined(HPCAP_IXGBEVF) )
	typedef union ixgbe_adv_rx_desc HW_RX_DESCR;
	
	#if defined(HPCAP_IXGBE)
		#define packet_buf(ring,i) ( (u8 *) ( ring->window[i >> IXGBE_SUBWINDOW_BITS] + (i & IXGBE_SUBWINDOW_MASK)*MAX_DESCR_SIZE ) )
		#define packet_dma(ring,i) ( (u64) ( ring->dma_window[i >> IXGBE_SUBWINDOW_BITS] + (i & IXGBE_SUBWINDOW_MASK) * MAX_DESCR_SIZE ) )
		typedef struct ixgbe_option DRIVER_OPTION;
		#define DRIVER_VALIDATE_OPTION(a,b) ixgbe_validate_option(a,b)
		#define HW_RELEASE_RX_DESCR(R,i) ixgbe_release_rx_desc((R), (i))
		typedef struct ixgbe_adapter HW_ADAPTER;
		typedef struct ixgbe_ring HW_RING;
		#define HW_RX_DESC(R,i) IXGBE_RX_DESC((R), (i))
	#elif defined(HPCAP_IXGBEVF)
		#define packet_buf(ring,i) ( (u8 *) ( ring->window[i >> IXGBEVF_SUBWINDOW_BITS] + (i & IXGBEVF_SUBWINDOW_MASK)*MAX_DESCR_SIZE ) )
		#define packet_dma(ring,i) ( (u64) ( ring->dma_window[i >> IXGBEVF_SUBWINDOW_BITS] + (i & IXGBEVF_SUBWINDOW_MASK) * MAX_DESCR_SIZE ) )
		typedef struct ixgbevf_option DRIVER_OPTION;
		#define DRIVER_VALIDATE_OPTION(a,b) ixgbevf_validate_option(a,b)
		#define HW_RELEASE_RX_DESCR(R,i) ixgbevf_release_rx_desc((R), (i))
		typedef struct ixgbevf_adapter HW_ADAPTER;
		typedef struct ixgbevf_ring HW_RING;
		#define HW_RX_DESC(R,i) IXGBEVF_RX_DESC((R), (i))
	#endif
#endif

#define MAX_LISTENERS 1
#define RX_MODE_READ 1
#define RX_MODE_MMAP 2

#define distance( primero, segundo, size) ( (primero<=segundo) ? (segundo-primero) : ( (size-primero)+segundo) )
#define used_bytes(plist) ( distance( (plist)->bufferRdOffset, (plist)->bufferWrOffset, (plist)->bufsz ) )
//#define avail_bytes(plist) ( distance( (plist)->bufferWrOffset, (plist)->bufferRdOffset, (plist)->bufsz ) )
#define avail_bytes(plist) ( ((plist)->bufsz) - used_bytes(plist) )
struct hpcap_listener {
	pid_t pid;
	int kill;
	u64 bufferWrOffset; //written by 1 producer
	u64 bufferRdOffset; //written by consumer
	int first;
	u64 bufsz;
};

struct hpcap_buf {
	/* Identifiers */
	int adapter;
	int queue;
	/* Status flags */
	atomic_t opened;
	int max_opened;
	atomic_t mapped;
	int created;
	/* RX-buf */
	char * bufferCopia;
	u64 bufSize;
	u64 bufferFileSize;
	struct task_struct *hilo;
	struct hpcap_listener global;
	atomic_t num_list;
	struct hpcap_listener listeners[MAX_LISTENERS];
	/* Atomic variables avoiding multiple concurrect accesses to the same methods */
	atomic_t readCount;
	atomic_t mmapCount;
	/* MISC */
	char name[100];
	struct cdev chard; /* Char device structure */
	#ifdef REMOVE_DUPS
		struct hpcap_dup_info ** dupTable;
	#endif
};

int hpcap_mmap(struct file *, struct vm_area_struct *);
int hpcap_open(struct inode *, struct file *);
int hpcap_release(struct inode *, struct file *);
ssize_t hpcap_read(struct file *, char __user *, size_t, loff_t *);
long hpcap_ioctl(struct file *,unsigned int, unsigned long);


extern int hpcap_stop_poll_threads(HW_ADAPTER *);
extern int hpcap_launch_poll_threads(HW_ADAPTER *);
extern int hpcap_unregister_chardev(HW_ADAPTER *);
extern int hpcap_register_chardev(HW_ADAPTER *, u64, u64, int);

#endif
