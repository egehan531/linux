#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/gpio.h>
#include <linux/gpio/consumer.h>

#define GPIO_PIN 714

static dev_t dev_num;
static struct class *dev_class;
static struct cdev my_cdev;
static char *kernel_buffer;
static unsigned int buffer_size = 512;
static int data_size = 0;

static int my_open(struct inode *inode, struct file *filp)
{
    pr_info("Device file açıldı.\n");
    return 0;
}

static int my_release(struct inode *inode, struct file *filp)
{
    pr_info("Device file kapandı.\n");
    return 0;
}

static ssize_t my_read(struct file *filp, char __user *user_buf, size_t count, loff_t *offset)
{
    ssize_t bytes_read;

    if (*offset >= data_size)
        return 0;

    if (count > data_size - *offset)
        count = data_size - *offset;

    bytes_read = copy_to_user(user_buf, kernel_buffer + *offset, count);
    if (bytes_read != 0)
        return -EFAULT;

    *offset += count;
    return count;
}

static ssize_t my_write(struct file *filp, const char __user *user_buf, size_t count, loff_t *offset)
{
    if (count >= buffer_size)
        count = buffer_size - 1;

    if (copy_from_user(kernel_buffer, user_buf, count))
        return -EFAULT;

    kernel_buffer[count] = '\0';
    data_size = count;
    *offset = 0;

    if (kernel_buffer[0] == '1') {
        gpio_set_value(GPIO_PIN, 1);
        pr_info("GPIO %d HIGH yapıldı.\n", GPIO_PIN);
    } else if (kernel_buffer[0] == '0') {
        gpio_set_value(GPIO_PIN, 0);
        pr_info("GPIO %d LOW yapıldı.\n", GPIO_PIN);
    } else {
        pr_warn("Geçersiz GPIO komutu! HIGH için 1, LOW için 0\n");
    }

    return count;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = my_open,
    .release = my_release,
    .read = my_read,
    .write = my_write,
    .unlocked_ioctl = NULL,
};

static int __init my_init(void)
{
    int num;

    kernel_buffer = kmalloc(buffer_size, GFP_KERNEL);
    if (!kernel_buffer)
        return -ENOMEM;

    num = alloc_chrdev_region(&dev_num, 0, 1, "mydevice");
    if (num < 0) {
        kfree(kernel_buffer);
        return num;
    }

    cdev_init(&my_cdev, &fops);
    num = cdev_add(&my_cdev, dev_num, 1);
    if (num < 0) {
        unregister_chrdev_region(dev_num, 1);
        kfree(kernel_buffer);
        return num;
    }

    dev_class = class_create(THIS_MODULE, "myast2500board");
    if (IS_ERR(dev_class)) {
        cdev_del(&my_cdev);
        unregister_chrdev_region(dev_num, 1);
        kfree(kernel_buffer);
        return PTR_ERR(dev_class);
    }

    if (IS_ERR(device_create(dev_class, NULL, dev_num, NULL, "mydevice"))) {
        class_destroy(dev_class);
        cdev_del(&my_cdev);
        unregister_chrdev_region(dev_num, 1);
        kfree(kernel_buffer);
        return -EINVAL;
    }

    if (gpio_request(GPIO_PIN, "mygpio") < 0) {
        device_destroy(dev_class, dev_num);
        class_destroy(dev_class);
        cdev_del(&my_cdev);
        unregister_chrdev_region(dev_num, 1);
        kfree(kernel_buffer);
        return -EBUSY;
    }

    if (gpio_direction_output(GPIO_PIN, 0) < 0) {
        gpio_free(GPIO_PIN);
        
        device_destroy(dev_class, dev_num);
        class_destroy(dev_class);
        cdev_del(&my_cdev);
        unregister_chrdev_region(dev_num, 1);
        kfree(kernel_buffer);
        return -EINVAL;
    }

    pr_info("Modül yüklendi. Major: %d, Minor: %d\n", MAJOR(dev_num), MINOR(dev_num));
    return 0;
}

static void __exit my_exit(void)
{
    gpio_direction_output(GPIO_PIN, 0);
    gpio_free(GPIO_PIN);

    device_destroy(dev_class, dev_num);
    class_destroy(dev_class);

    cdev_del(&my_cdev);
    unregister_chrdev_region(dev_num, 1);

    kfree(kernel_buffer);

    pr_info("Modül kaldırıldı.\n");
}


module_init(my_init);
module_exit(my_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Egehan");
MODULE_DESCRIPTION("AST2500 Driver");