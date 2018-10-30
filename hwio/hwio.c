#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/signal.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/mman.h>

#define	MMAP_ALIGN	4096
#define	MMAP_DEVICE	"/dev/mem"

static void *iomem_map(unsigned long phys, unsigned long len,
		       unsigned long *map_phys)
{
	void *virt;
	int fd;

	fd = open(MMAP_DEVICE, O_RDWR|O_SYNC);
	if (fd < 0) {
		printf("Fail, open %s, %s\n", MMAP_DEVICE, strerror(errno));
		return 0;
	}

	if (phys & (MMAP_ALIGN - 1))
		phys = (phys & ~(MMAP_ALIGN - 1));

	if (len & (MMAP_ALIGN - 1))
		len = (len & ~(MMAP_ALIGN - 1)) + MMAP_ALIGN;

	virt = mmap((void *)0,
			len,
			PROT_READ|PROT_WRITE, MAP_SHARED,
			fd,
			(off_t)phys);
	if ((long)virt == -1) {
		printf("Fail: map PV:0x%08x, Len:%d, %s\n",
			phys, len, strerror(errno));
		goto _err_map;
	}

	if (map_phys)
		*map_phys = phys;

_err_map:
	close(fd);
	return virt;
}

static void iomem_free(void *virt, unsigned long len)
{
	if (virt && len)
		munmap(virt, len);
}

void print_usage(void)
{
	printf("usage: options\n"
	       "-a physical address (hex)\n"
	       "-w write data (hex)\n"
	       "-l read length (hex)\n"
	       "-n line feed\n"
	);
}

#define readl(a)	(*(unsigned long *)(a))
#define writel(v, a)	(*(unsigned long *)(a) = v)

int main(int argc, char **argv)
{
	int opt;
	unsigned long addr = 0, data = 0, size = 4;
	unsigned long map_phys = 0;
	void *virt;
	bool wop = false, lfeed = false;
	int i;

	while (-1 != (opt = getopt(argc, argv, "ha:w:l:n"))) {
		switch (opt) {
		case 'a':
			addr = strtoul(optarg, NULL, 16);
			break;
		case 'w':
			data = strtoul(optarg, NULL, 16);
			wop = 1;
			break;
		case 'l':
			size = strtoul(optarg, NULL, 16);
			break;
		case 'n':
			lfeed = 1;
			break;
		case 'h':
			print_usage();
			exit(0);
		default:
			break;
		}
	}

	/* align 4 byte */
	addr &= ~0x3;

	if (!addr) {
		printf("Fail, no IO address\n");
		print_usage();
		return -EINVAL;
	}

	virt = iomem_map(addr, size, &map_phys);
	if (!virt)
		return -EINVAL;

	if (wop) {
		printf("\n(W) 0x%08x: 0x%08x\n", addr, data);
		writel(data, virt + (addr - map_phys));
	} else {
		if (size < 4)
			size = 4;

		for (i = 0; i < (int)(size/4); i++, addr += 4) {
			unsigned long val = readl(virt + (addr - map_phys));

			if (!lfeed) {
				if (!(i%4))
					printf("\n0x%08x: ", addr);
				printf("0x%08x ", val);
			} else {
				printf("0x%08x: 0x%08x\n", addr, val);
			}
		}
	}
	printf("\n");

_exit:
	return 0;
}
