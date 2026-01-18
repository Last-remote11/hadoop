struct vqueue {
  struct bpf_spin_lock lock;
  /* 4 byte hole */
  unsigned long long lasttime;	/* In ns */
  uint64_t credit;			/* In bytes */
  unsigned int rate;		/* In bytes per NS << 20 */
};