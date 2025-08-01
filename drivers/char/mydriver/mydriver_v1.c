#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/gpio.h>
#include <linux/gpio/consumer.h>
#include <linux/ioctl.h>
#include <linux/interrupt.h>

#define GPIO_PIN 706
#define DUMMY_INTERRUPT 714

#define MAGIC_NUM 'G'
#define GPIO_SET_HIGH _IO(MAGIC_NUM, 0)
#define GPIO_SET_LOW _IO(MAGIC_NUM, 1)

static dev_t dev_num;
static struct class *dev_class;
static struct cdev my_cdev;
static char *kernel_buffer;
static unsigned int buffer_size = 1024;

static int irq_number;
static unsigned int irq_trigger_count = 0;

static int my_open(struct inode *inode, struct file *filp)
{
    pr_info("mydevice -> Device file açıldı.\n");
    return 0;
}

static int my_release(struct inode *inode, struct file *filp)
{
    pr_info("mydevice -> Device file kapandı.\n");
    return 0;
}

static long my_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    switch (cmd) {
        case GPIO_SET_HIGH:
            gpio_set_value(GPIO_PIN, 1);
            pr_info("GPIO %d IOCTL ile HIGH yapıldı.\n", GPIO_PIN);
            break;

        case GPIO_SET_LOW:
            gpio_set_value(GPIO_PIN, 0);
            pr_info("GPIO %d IOCTL ile LOW yapıldı.\n", GPIO_PIN);
            break;

        default:
            pr_warn("Geçersiz IOCTL komutu: %u\n", cmd);
            return -EINVAL;
    }

    return 0;
}

static irqreturn_t irq_handler(int irq, void *dev_id)
{
    static bool led_state = false;
    led_state = !led_state;
    gpio_set_value(GPIO_PIN, led_state);

    irq_trigger_count++;
    pr_info("GPIO %d interrupted. Toplam: %u\n", DUMMY_INTERRUPT, irq_trigger_count);
    return IRQ_HANDLED;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = my_open,
    .release = my_release,
    .read = NULL,
    .write = NULL,
    .unlocked_ioctl = my_ioctl,
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

    dev_class = class_create("myast2500board");
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

    if (gpio_request(DUMMY_INTERRUPT, "myirq") < 0) {
        gpio_free(GPIO_PIN);

        device_destroy(dev_class, dev_num);
        class_destroy(dev_class);
        cdev_del(&my_cdev);
        unregister_chrdev_region(dev_num, 1);
        kfree(kernel_buffer);
        return -EBUSY;
    }

    if (gpio_direction_input(DUMMY_INTERRUPT) < 0) {
        gpio_free(DUMMY_INTERRUPT);
        gpio_free(GPIO_PIN);

        device_destroy(dev_class, dev_num);
        class_destroy(dev_class);
        cdev_del(&my_cdev);
        unregister_chrdev_region(dev_num, 1);
        kfree(kernel_buffer);
        return -EINVAL;
    }

    irq_number = gpio_to_irq(DUMMY_INTERRUPT);

    if (irq_number < 0) {
        gpio_free(DUMMY_INTERRUPT);
        gpio_free(GPIO_PIN);

        device_destroy(dev_class, dev_num);
        class_destroy(dev_class);
        cdev_del(&my_cdev);
        unregister_chrdev_region(dev_num, 1);
        kfree(kernel_buffer);
        return irq_number;
    }

    if (request_irq(irq_number, irq_handler, IRQF_TRIGGER_RISING, "dummy_irq", NULL)) {
        gpio_free(DUMMY_INTERRUPT);
        gpio_free(GPIO_PIN);

        device_destroy(dev_class, dev_num);
        class_destroy(dev_class);
        cdev_del(&my_cdev);
        unregister_chrdev_region(dev_num, 1);
        kfree(kernel_buffer);
        return -EBUSY;
    }

    pr_info("mydevice -> Modül yüklendi. Major: %d, Minor: %d\n", MAJOR(dev_num), MINOR(dev_num));
    pr_info("myast2500board -> Class oluştu.\n");
    pr_info("mygpio -> Pin alındı.\n");
    pr_info("myirq -> Pin alındı.\n");
    return 0;
}

static void __exit my_exit(void)
{
    free_irq(irq_number, NULL);
    gpio_free(DUMMY_INTERRUPT);

    gpio_direction_output(GPIO_PIN, 0);
    gpio_free(GPIO_PIN);

    device_destroy(dev_class, dev_num);
    class_destroy(dev_class);

    cdev_del(&my_cdev);
    unregister_chrdev_region(dev_num, 1);

    kfree(kernel_buffer);

    pr_info("mydevice -> Modül kaldırıldı.\n");
}


module_init(my_init);
module_exit(my_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Egehan");
MODULE_DESCRIPTION("AST2500 Driver");
