#ifndef __ASM_X86_HVM_RTC_H__
#define __ASM_X86_HVM_RTC_H__

#define domain_vrtc(x) (&(x)->arch.hvm_domain.pl_time.vrtc)
#define vcpu_vrtc(x)   (domain_vrtc((x)->domain))

int rtc_ioport_write(void *opaque, uint32_t addr, uint32_t data);
uint32_t rtc_ioport_read(RTCState *s, uint32_t addr);

#endif
