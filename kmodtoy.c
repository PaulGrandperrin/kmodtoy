#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/pagemap.h> // for PAGE_CACHE*
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <asm/uaccess.h>
#include <linux/kallsyms.h> //kallsyms_lookup_name


#include <linux/bio.h> //??
#include <linux/blk_types.h> //???

#include <linux/sched.h> //task_pid_nr

//#include <linux/vfs.h>

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Paul Grandperrin <paul.grandperrin@gmail.com>");
MODULE_DESCRIPTION("A toy filesystem");

/* - - - - - - - - - - - - - - - - */


#define GPF_DISABLE write_cr0(read_cr0() & (~ 0x10000))
#define GPF_ENABLE write_cr0(read_cr0() | 0x10000)
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/unistd.h>
//#include <asm/semaphore.h>
#include <asm/cacheflush.h>

void **sys_call_table;

asmlinkage int (*original_call) (const char*, int, int);

asmlinkage int our_sys_open(const char* file, int flags, int mode)
{
   printk(KERN_INFO "A file was opened: %s\n by %d", file,  task_pid_nr(current));
   return original_call(file, flags, mode);
}

// int set_page_rw(long unsigned int _addr)
// {
//    struct page *pg;
//    pgprot_t prot;
//    pg = virt_to_page(_addr);
//    prot.pgprot = VM_READ | VM_WRITE;
//    return change_page_attr(pg, 1, prot);
// }

static void disable_page_protection(void) {

    unsigned long value;
    asm volatile("mov %%cr0,%0" : "=r" (value));
    if (value & 0x00010000) {
            value &= ~0x00010000;
            asm volatile("mov %0,%%cr0": : "r" (value));
    }
}

static void enable_page_protection(void) {

    unsigned long value;
    asm volatile("mov %%cr0,%0" : "=r" (value));
    if (!(value & 0x00010000)) {
            value |= 0x00010000;
            asm volatile("mov %0,%%cr0": : "r" (value));
    }
}

static void set_addr_rw(unsigned long addr) {

    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);

    if (pte->pte &~ _PAGE_RW) pte->pte |= _PAGE_RW;

}

static void set_addr_ro(unsigned long addr) {

    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);

    pte->pte = pte->pte &~_PAGE_RW;

}

//-------


struct list_msgs
{
    struct list_msgs* next;
    char* msg;
};

static struct list_msgs* index;

static struct proc_dir_entry *proc_entry;
static struct kmem_cache *slab_index, *slab_msgs;


int kmt_read(char *page, char **start, off_t off,
              int count, int *eof, void *data)
{
  int len=0;
  struct list_msgs* i;
  
  if (off > 0)
  {
    *eof = 1;
    return 0;
  }

  
  i=index;

  while(i)
  {
        len += sprintf(&page[len], "%s",i->msg);
        i=i->next;
  }
  
  return len;
}

int kmt_write(struct file *file, const char __user *buffer,
               unsigned long count, void *data)
{
    char* msg;
    struct list_msgs* cel;
    
    if(count >= 256)
    {
        printk(KERN_INFO "Message too long\n");
        return -ENOSPC;
    }
    
    msg = kmem_cache_alloc( slab_msgs, GFP_KERNEL );
    cel = kmem_cache_alloc( slab_index, GFP_KERNEL );
    
    if (copy_from_user( msg, buffer, count ))
    {
        return -EFAULT;
    }
    msg[count]=0;

    cel->msg=msg;
    cel->next=NULL;
    
    if(!index)
    {
        index=cel;
        printk(KERN_INFO "Ecriture de l'index\n");
    }
    else
    {
        struct list_msgs* i=index;
        while(i->next)
        {
            i=i->next;
        }

        printk(KERN_INFO "Ecriture dans une cellule\n");
        i->next=cel;
    }

    return count;
}

//----------

struct wtfs_super_block {
    __le32 s_magic;
    __le32 s_start;
    __le32 s_end;
    __le32 s_from;
    __le32 s_to;
    __s32 s_bfrom;
    __s32 s_bto;
    char  s_fsname[6];
    char  s_volume[6];
    __u32 s_padding[118];
};

struct wtfs_inode {
    __le16 i_ino;
    __u16 i_unused;
    __le32 i_sblock;
    __le32 i_eblock;
    __le32 i_eoffset;
    __le32 i_vtype;
    __le32 i_mode;
    __le32 i_uid;
    __le32 i_gid;
    __le32 i_nlink;
    __le32 i_atime;
    __le32 i_mtime;
    __le32 i_ctime;
    __u32 i_padding[4];
};

struct wtfs_sb_info {
    unsigned long si_blocks;
    unsigned long si_freeb;
    unsigned long si_freei;
    unsigned long si_lf_eblk;
    unsigned long si_lasti;
    unsigned long *si_imap;
    struct mutex wtfs_lock;
};

struct wtfs_inode_info {
    unsigned long i_dsk_ino; /* inode number from the disk, can be 0 */
    unsigned long i_sblock;
    unsigned long i_eblock;
    struct inode vfs_inode;
};

static struct kmem_cache * wtfs_inode_cachep;

#define WTFS_MAGIC 0xCACABEBE
#define TMPSIZE 20
/* - - - - - - - - - - - - - - - - */

static ssize_t wtfs_write_file(struct file *filp, const char *buf,
        size_t count, loff_t *offset)
{
    atomic_t *counter = (atomic_t *) filp->private_data;
    char tmp[TMPSIZE];

    if (*offset != 0)
        return -EINVAL;
    if (count >= TMPSIZE)
        return -EINVAL;

    memset(tmp, 0, TMPSIZE);
    if (copy_from_user(tmp, buf, count))
        return -EFAULT;
    atomic_set(counter, simple_strtol(tmp, NULL, 10));
    return count;
}


static ssize_t wtfs_read_file(struct file *filp, char *buf,
        size_t count, loff_t *offset)
{
    atomic_t *counter = (atomic_t *) filp->private_data;
    int v, len;
    char tmp[TMPSIZE];
/*
 * Encode the value, and figure out how much of it we can pass back.
 */
    v = atomic_read(counter);
    if (*offset > 0)
        v -= 1;  /* the value returned when offset was zero */
    else
        atomic_inc(counter);
    len = snprintf(tmp, TMPSIZE, "%d\n", v);
    if (*offset > len)
        return 0;
    if (count > len - *offset)
        count = len - *offset;
/*
 * Copy it back, increment the offset, and we're done.
 */
    if (copy_to_user(buf, tmp + *offset, count))
        return -EFAULT;
    *offset += count;
    return count;
}

static int wtfs_open(struct inode *inode, struct file *filp)
{
    filp->private_data = inode->i_private;
    return 0;
}

static struct file_operations wtfs_file_ops = {
        .open   = wtfs_open,
        .read   = wtfs_read_file,
        .write      = wtfs_write_file,
};



static struct inode *wtfs_make_inode(struct super_block *sb, int mode)
{
    struct inode *ret = new_inode(sb);

    if (ret) {
        ret->i_mode = mode;
        ret->i_uid = ret->i_gid = 0;
        ret->i_blocks = 0;
        ret->i_atime = ret->i_mtime = ret->i_ctime = CURRENT_TIME;
    }
    return ret;
}





static struct dentry *wtfs_create_file (struct super_block *sb,
        struct dentry *dir, const char *name,
        atomic_t *counter)
{
    struct dentry *dentry;
    struct inode *inode;
    struct qstr qname;
    
    qname.name = name;
    qname.len = strlen (name);
    qname.hash = full_name_hash(name, qname.len);
    dentry = d_alloc(dir, &qname);
    if (! dentry)
        goto out;
    
    inode = wtfs_make_inode(sb, S_IFREG | 0644);
    if (! inode)
        goto out_dput;
    inode->i_fop = &wtfs_file_ops;
    inode->i_private = counter;
    
    d_add(dentry, inode);
    return dentry;
    
    out_dput:
    dput(dentry);
    out:
    return 0;
}


static atomic_t counter;

static void wtfs_create_files (struct super_block *sb, 
                                  struct dentry *root)
{
    atomic_set(&counter, 0);
    wtfs_create_file(sb, root, "counter", &counter);
}




static struct super_operations wtfs_s_ops =
{
    .statfs     = simple_statfs,
    .drop_inode = generic_delete_inode,
};

static int wtfs_fill_super(struct super_block *s, void *data, int silent)
{
    struct inode *root;
    struct dentry *root_dentry;
    
    
    s->s_blocksize = PAGE_CACHE_SIZE;
    s->s_blocksize_bits= PAGE_CACHE_SHIFT;
    s->s_magic= WTFS_MAGIC;
    s->s_op=&wtfs_s_ops;
    
    root = wtfs_make_inode(s, S_IFDIR | 0755);
    if (! root)
        goto out;
    root->i_op = &simple_dir_inode_operations;
    root->i_fop = &simple_dir_operations;
    
    root_dentry = d_alloc_root(root);
    if (! root_dentry)
        goto out_iput;
    s->s_root = root_dentry;

    wtfs_create_files(s, root_dentry);
    
    return 0;
    
    out_iput:
    iput(root);
    out:
    return -ENOMEM;
    
}


static void init_once(void *foo)
{
    struct wtfs_inode_info *bi = foo;

    inode_init_once(&bi->vfs_inode);    //kernel
}

static struct dentry *wtfs_mount(struct file_system_type *fs_type,
    int flags, const char *dev_name, void *data)
{
    printk(KERN_INFO "WTFS: mounting %s (%s)",dev_name,(char*)data); // FIXME data?
    return mount_bdev(fs_type, flags, dev_name, data, wtfs_fill_super);
}


static int init_inodecache(void)
{
    wtfs_inode_cachep = kmem_cache_create("wtfs_inode_cache", //kernel
                         sizeof(struct wtfs_inode_info),
                         0, (SLAB_RECLAIM_ACCOUNT|
                        SLAB_MEM_SPREAD),
                         init_once);
    if (wtfs_inode_cachep == NULL)
        return -ENOMEM;
    return 0;
}

static void destroy_inodecache(void)
{
    kmem_cache_destroy(wtfs_inode_cachep); //kernel
}

static struct file_system_type wtfs_type=
{
        .name           = "wtfs",
        .fs_flags       = FS_REQUIRES_DEV,
        .mount          = wtfs_mount,
        .kill_sb        = kill_litter_super, //FIXME block
        .owner          = THIS_MODULE,
        .next           = NULL,
};

static int __init wtfs_init(void)
{
    int err;
    printk(KERN_INFO "Loading WTFS");
    
    err = init_inodecache();
    if (err)
        goto out1;
    
    err = register_filesystem(&wtfs_type); //kernel
    if(err)
        goto out;
    
    printk(KERN_INFO "WTFS loaded");
    
    
    //----------------
        proc_entry = create_proc_entry( "kmodtoy", 0644, NULL );

    if (proc_entry == NULL)
    {
      printk(KERN_INFO "KModToy: Couldn't create proc entry\n");
      return -ENOMEM;
    }

    proc_entry->read_proc = kmt_read;
    proc_entry->write_proc = kmt_write;


    //Allocation du slab
    slab_index = kmem_cache_create(
                  "kmodtoy_index",       /* Name */
                  sizeof(struct list_msgs),         /* Object Size */
                  0,                     /* Alignment */
                  SLAB_HWCACHE_ALIGN,    /* Flags */
                  NULL );                /* Constructor/Deconstructor */

    //Allocation du slab
    slab_msgs = kmem_cache_create(
                  "kmodtoy_msgs",        /* Name */
                  256,                   /* Object Size */
                  0,                     /* Alignment */
                  SLAB_HWCACHE_ALIGN,    /* Flags */
                  NULL );                /* Constructor/Deconstructor */

    index=NULL;
    
    //-----
     // sys_call_table address in System.map
    sys_call_table = (void*)0xffffffff81401230;
    //GPF_DISABLE;
    set_addr_rw((unsigned long)sys_call_table);
    
    original_call = sys_call_table[__NR_open];

    
    sys_call_table[__NR_open] = our_sys_open;
    set_addr_ro((unsigned long)sys_call_table);
    //GPF_ENABLE;
    
    
    
    //-----
    
    printk(KERN_INFO "KModToy loaded\n");
    
	
	//--------
	
	struct bio *b;
	bio = bio_alloc(GFP_NOIO, BIO_MAX_PAGES);
	bio->bi_sector = bh->b_blocknr * (bh->b_size >> 9);
	bio->bi_bdev = bh->b_bdev;
	bio->bi_private = io->io_end = io_end;
	bio->bi_end_io = ext4_end_bio;
	
	
	
	return 0;
    
    
    out:
    destroy_inodecache();
    out1:
    printk(KERN_INFO "WTFS not loaded");
    return err;
    
}

static void __exit wtfs_exit(void)
{
    struct list_msgs* i=index,*t;
    printk(KERN_INFO "Unloading WTFS");
    unregister_filesystem(&wtfs_type); //kernel
    destroy_inodecache();
    printk(KERN_INFO "WTFS unloaded");
    //-----------------------

    remove_proc_entry("kmodtoy", NULL);//MODULE_NAME

    while(i)
    {
        t=i->next;
        kmem_cache_free( slab_msgs, i->msg);
        kmem_cache_free( slab_index, i);
        i=t;
    }
    
    if (slab_index) kmem_cache_destroy(slab_index);
    if (slab_msgs) kmem_cache_destroy(slab_msgs);
    
    //-------

    //GPF_DISABLE;
    set_addr_rw((unsigned long)sys_call_table);
    sys_call_table[__NR_open] = original_call;
    set_addr_ro((unsigned long)sys_call_table);
    //GPF_ENABLE;
    //----
    printk(KERN_INFO "KModToy unloaded\n");
    return;
}





module_init(wtfs_init); //kernel
module_exit(wtfs_exit); //kernel