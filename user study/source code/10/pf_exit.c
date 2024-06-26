static void __exit pf_exit(void)
{
    struct pf_unit *pf;
    int unit;
    unregister_blkdev(major, name);
    for (pf = units, unit = 0; unit < PF_UNITS; pf++, unit++)
    {
        if (!pf->disk)
            continue;

        if (pf->present)
            del_gendisk(pf->disk);

        blk_cleanup_queue(pf->disk->queue);
        blk_mq_free_tag_set(&pf->tag_set);
        put_disk(pf->disk);

        if (pf->present)
            pi_release(pf->pi);
    }
}