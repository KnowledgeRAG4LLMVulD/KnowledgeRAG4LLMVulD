/**
 * usb_register_dev - register a USB device, and ask for a minor number
 * @intf: pointer to the usb_interface that is being registered
 * @class_driver: pointer to the usb_class_driver for this device
 *
 * This should be called by all USB drivers that use the USB major number.
 * If CONFIG_USB_DYNAMIC_MINORS is enabled, the minor number will be
 * dynamically allocated out of the list of available ones.  If it is not
 * enabled, the minor number will be based on the next available free minor,
 * starting at the class_driver->minor_base.
 *
 * This function also creates a usb class device in the sysfs tree.
 *
 * usb_deregister_dev() must be called when the driver is done with
 * the minor numbers given out by this function.
 *
 * Return: -EINVAL if something bad happens with trying to register a
 * device, and 0 on success.
 */
int usb_register_dev(struct usb_interface *intf,
                     struct usb_class_driver *class_driver)
{
    int retval;
    int minor_base = class_driver->minor_base;
    int minor;
    char name[20];

#ifdef CONFIG_USB_DYNAMIC_MINORS
    /*
     * We don't care what the device tries to start at, we want to start
     * at zero to pack the devices into the smallest available space with
     * no holes in the minor range.
     */
    minor_base = 0;
#endif

    if (class_driver->fops == NULL)
        return -EINVAL;
    if (intf->minor >= 0)
        return -EADDRINUSE;

    mutex_lock(&init_usb_class_mutex);
    retval = init_usb_class();
    mutex_unlock(&init_usb_class_mutex);

    if (retval)
        return retval;

    dev_dbg(&intf->dev, "looking for a minor, starting at %d\n", minor_base);

    down_write(&minor_rwsem);
    for (minor = minor_base; minor < MAX_USB_MINORS; ++minor)
    {
        if (usb_minors[minor])
            continue;

        usb_minors[minor] = class_driver->fops;
        intf->minor = minor;
        break;
    }
    if (intf->minor < 0)
    {
        up_write(&minor_rwsem);
        return -EXFULL;
    }

    /* create a usb class device for this usb interface */
    snprintf(name, sizeof(name), class_driver->name, minor - minor_base);
    intf->usb_dev = device_create(usb_class->class, &intf->dev,
                                  MKDEV(USB_MAJOR, minor), class_driver,
                                  "%s", kbasename(name));
    if (IS_ERR(intf->usb_dev))
    {
        usb_minors[minor] = NULL;
        intf->minor = -1;
        retval = PTR_ERR(intf->usb_dev);
    }
    up_write(&minor_rwsem);
    return retval;
}
EXPORT_SYMBOL_GPL(usb_register_dev);