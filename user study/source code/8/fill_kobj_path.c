static void fill_kobj_path(const struct kobject *kobj, char *path, int length)
{
    const struct kobject *parent;

    --length;
    for (parent = kobj; parent; parent = parent->parent)
    {
        int cur = strlen(kobject_name(parent));
        /* back up enough to print this name with '/' */
        length -= cur;
        memcpy(path + length, kobject_name(parent), cur);
        *(path + --length) = '/';
    }

    pr_debug("kobject: '%s' (%p): %s: path = '%s'\n", kobject_name(kobj),
             kobj, __func__, path);
}