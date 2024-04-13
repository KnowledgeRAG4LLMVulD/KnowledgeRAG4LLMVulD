char *
isdn_net_newslave(char *parm)
{
    char *p = strchr(parm, ',');
    isdn_net_dev *n;
    char newname[10];

    if (p)
    {
        /* Slave-Name MUST not be empty */
        if (!strlen(p + 1))
            return NULL;
        strcpy(newname, p + 1);
        *p = 0;
        /* Master must already exist */
        if (!(n = isdn_net_findif(parm)))
            return NULL;
        /* Master must be a real interface, not a slave */
        if (n->local->master)
            return NULL;
        /* Master must not be started yet */
        if (isdn_net_device_started(n))
            return NULL;
        return (isdn_net_new(newname, n->dev));
    }
    return NULL;
}