/*
 * Check if the disk has been changed or if a change has been faked.
 */
static unsigned int floppy_check_events(struct gendisk *disk,
                                        unsigned int clearing)
{
    int drive = (long)disk->private_data;

    if (test_bit(FD_DISK_CHANGED_BIT, &UDRS->flags) ||
        test_bit(FD_VERIFY_BIT, &UDRS->flags))
        return DISK_EVENT_MEDIA_CHANGE;

    if (time_after(jiffies, UDRS->last_checked + UDP->checkfreq))
    {
        lock_fdc(drive, false);
        poll_drive(false, 0);
        process_fd_request();
    }

    if (test_bit(FD_DISK_CHANGED_BIT, &UDRS->flags) ||
        test_bit(FD_VERIFY_BIT, &UDRS->flags) ||
        test_bit(drive, &fake_change) ||
        drive_no_geom(drive))
        return DISK_EVENT_MEDIA_CHANGE;
    return 0;
}