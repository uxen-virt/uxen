#ifndef __X86_64_UACCESS_H
#define __X86_64_UACCESS_H

#define access_ok(addr, size)                                      \
    (current->always_access_ok ||                                  \
     UI_HOST_CALL(ui_user_access_ok, current->user_access_opaque,  \
                  (void *)(addr), size))

#define array_access_ok(addr, count, size) \
    (access_ok(addr, (count)*(size)))

#define __put_user_size(x,ptr,size,retval,errret)			\
do {									\
	retval = 0;							\
	switch (size) {							\
	case 1: __put_user_asm(x,ptr,retval,"b","b","iq",errret);break;	\
	case 2: __put_user_asm(x,ptr,retval,"w","w","ir",errret);break; \
	case 4: __put_user_asm(x,ptr,retval,"l","k","ir",errret);break;	\
	case 8: __put_user_asm(x,ptr,retval,"q","","ir",errret);break;	\
	default: __put_user_bad();					\
	}								\
} while (0)

#define __get_user_size(x,ptr,size,retval,errret)			\
do {									\
	retval = 0;							\
	switch (size) {							\
	case 1: __get_user_asm(x,ptr,retval,"b","b","=q",errret);break;	\
	case 2: __get_user_asm(x,ptr,retval,"w","w","=r",errret);break;	\
	case 4: __get_user_asm(x,ptr,retval,"l","k","=r",errret);break;	\
	case 8: __get_user_asm(x,ptr,retval,"q","","=r",errret); break;	\
	default: __get_user_bad();					\
	}								\
} while (0)

#endif /* __X86_64_UACCESS_H */
