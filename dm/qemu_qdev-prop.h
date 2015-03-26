
#ifndef _QEMU_QDEV_PROP_H_
#define _QEMU_QDEV_PROP_H_

extern PropertyInfo qdev_prop_bit;
extern PropertyInfo qdev_prop_uint8;
extern PropertyInfo qdev_prop_uint16;
extern PropertyInfo qdev_prop_uint32;
extern PropertyInfo qdev_prop_int32;
extern PropertyInfo qdev_prop_uint64;
extern PropertyInfo qdev_prop_hex8;
extern PropertyInfo qdev_prop_hex32;
extern PropertyInfo qdev_prop_hex64;
extern PropertyInfo qdev_prop_string;
extern PropertyInfo qdev_prop_chr;
extern PropertyInfo qdev_prop_ptr;
extern PropertyInfo qdev_prop_macaddr;
extern PropertyInfo qdev_prop_drive;
extern PropertyInfo qdev_prop_netdev;
extern PropertyInfo qdev_prop_vlan;
extern PropertyInfo qdev_prop_pci_devfn;

#define DEFINE_PROP(_name, _state, _field, _prop, _type) { \
        .name      = (_name),                                    \
        .info      = &(_prop),                                   \
        .offset    = offsetof(_state, _field)                    \
            + type_check(_type,typeof_field(_state, _field)),    \
        }
#define DEFINE_PROP_DEFAULT(_name, _state, _field, _defval, _prop, _type) { \
        .name      = (_name),                                           \
        .info      = &(_prop),                                          \
        .offset    = offsetof(_state, _field)                           \
            + type_check(_type,typeof_field(_state, _field)),           \
        .defval    = (_type[]) { _defval },                             \
        }
#define DEFINE_PROP_BIT(_name, _state, _field, _bit, _defval) {  \
        .name      = (_name),                                    \
        .info      = &(qdev_prop_bit),                           \
        .bitnr    = (_bit),                                      \
        .offset    = offsetof(_state, _field)                    \
            + type_check(uint32_t,typeof_field(_state, _field)), \
        .defval    = (bool[]) { (_defval) },                     \
        }

#define DEFINE_PROP_UINT8(_n, _s, _f, _d)                       \
    DEFINE_PROP_DEFAULT(_n, _s, _f, _d, qdev_prop_uint8, uint8_t)
#define DEFINE_PROP_UINT16(_n, _s, _f, _d)                      \
    DEFINE_PROP_DEFAULT(_n, _s, _f, _d, qdev_prop_uint16, uint16_t)
#define DEFINE_PROP_UINT32(_n, _s, _f, _d)                      \
    DEFINE_PROP_DEFAULT(_n, _s, _f, _d, qdev_prop_uint32, uint32_t)
#define DEFINE_PROP_INT32(_n, _s, _f, _d)                      \
    DEFINE_PROP_DEFAULT(_n, _s, _f, _d, qdev_prop_int32, int32_t)
#define DEFINE_PROP_UINT64(_n, _s, _f, _d)                      \
    DEFINE_PROP_DEFAULT(_n, _s, _f, _d, qdev_prop_uint64, uint64_t)
#define DEFINE_PROP_HEX8(_n, _s, _f, _d)                       \
    DEFINE_PROP_DEFAULT(_n, _s, _f, _d, qdev_prop_hex8, uint8_t)
#define DEFINE_PROP_HEX32(_n, _s, _f, _d)                       \
    DEFINE_PROP_DEFAULT(_n, _s, _f, _d, qdev_prop_hex32, uint32_t)
#define DEFINE_PROP_HEX64(_n, _s, _f, _d)                       \
    DEFINE_PROP_DEFAULT(_n, _s, _f, _d, qdev_prop_hex64, uint64_t)
#define DEFINE_PROP_PCI_DEVFN(_n, _s, _f, _d)                   \
    DEFINE_PROP_DEFAULT(_n, _s, _f, _d, qdev_prop_pci_devfn, uint32_t)

#define DEFINE_PROP_PTR(_n, _s, _f)             \
    DEFINE_PROP(_n, _s, _f, qdev_prop_ptr, void*)
#define DEFINE_PROP_CHR(_n, _s, _f)             \
    DEFINE_PROP(_n, _s, _f, qdev_prop_chr, CharDriverState*)
#define DEFINE_PROP_STRING(_n, _s, _f)             \
    DEFINE_PROP(_n, _s, _f, qdev_prop_string, char*)
#define DEFINE_PROP_NETDEV(_n, _s, _f)             \
    DEFINE_PROP(_n, _s, _f, qdev_prop_netdev, VLANClientState*)
#define DEFINE_PROP_VLAN(_n, _s, _f)             \
    DEFINE_PROP(_n, _s, _f, qdev_prop_vlan, VLANState*)
#define DEFINE_PROP_DRIVE(_n, _s, _f) \
    DEFINE_PROP(_n, _s, _f, qdev_prop_drive, BlockDriverState *)
#define DEFINE_PROP_MACADDR(_n, _s, _f)         \
    DEFINE_PROP(_n, _s, _f, qdev_prop_macaddr, MACAddr)

#define DEFINE_PROP_END_OF_LIST()               \
    {}

/* Set properties between creation and init.  */
void *qdev_get_prop_ptr(DeviceState *dev, Property *prop);
int qdev_prop_exists(DeviceState *dev, const char *name);
int qdev_prop_parse(DeviceState *dev, const char *name, const char *value);
void qdev_prop_set(DeviceState *dev, const char *name, void *src, enum PropertyType type);
void qdev_prop_set_bit(DeviceState *dev, const char *name, bool value);
void qdev_prop_set_uint8(DeviceState *dev, const char *name, uint8_t value);
void qdev_prop_set_uint16(DeviceState *dev, const char *name, uint16_t value);
void qdev_prop_set_uint32(DeviceState *dev, const char *name, uint32_t value);
void qdev_prop_set_int32(DeviceState *dev, const char *name, int32_t value);
void qdev_prop_set_uint64(DeviceState *dev, const char *name, uint64_t value);
void qdev_prop_set_string(DeviceState *dev, const char *name, char *value);
void qdev_prop_set_chr(DeviceState *dev, const char *name, CharDriverState *value);
// void qdev_prop_set_netdev(DeviceState *dev, const char *name, VLANClientState *value);
// void qdev_prop_set_vlan(DeviceState *dev, const char *name, VLANState *value);
int qdev_prop_set_drive(DeviceState *dev, const char *name, BlockDriverState *value) QEMU_WARN_UNUSED_RESULT;
void qdev_prop_set_drive_nofail(DeviceState *dev, const char *name, BlockDriverState *value);
void qdev_prop_set_macaddr(DeviceState *dev, const char *name, uint8_t *value);
/* FIXME: Remove opaque pointer properties.  */
void qdev_prop_set_ptr(DeviceState *dev, const char *name, void *value);
void qdev_prop_set_defaults(DeviceState *dev, Property *props);

#if 0
void qdev_prop_register_global_list(GlobalProperty *props);
void qdev_prop_set_globals(DeviceState *dev);
#endif

#endif	/* _QEMU_QDEV_PROP_H_ */
