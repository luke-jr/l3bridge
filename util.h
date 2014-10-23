#ifndef L3B_UTIL_H
#define L3B_UTIL_H

static inline
uint8_t upk_u8(const void * const bufp, const int offset)
{
	const uint8_t * const buf = bufp;
	return buf[offset];
}

#define upk_u8be(buf, offset)  upk_u8(buf, offset)

static inline
uint16_t upk_u16be(const void * const bufp, const int offset)
{
	const uint8_t * const buf = bufp;
	return (((uint16_t)buf[offset+0]) <<    8)
	     | (((uint16_t)buf[offset+1]) <<    0);
}

static inline
uint32_t upk_u32be(const void * const bufp, const int offset)
{
	const uint8_t * const buf = bufp;
	return (((uint32_t)buf[offset+0]) << 0x18)
	     | (((uint32_t)buf[offset+1]) << 0x10)
	     | (((uint32_t)buf[offset+2]) <<    8)
	     | (((uint32_t)buf[offset+3]) <<    0);
}

static inline
uint64_t upk_u64be(const void * const bufp, const int offset)
{
	const uint8_t * const buf = bufp;
	return (((uint64_t)buf[offset+0]) << 0x38)
	     | (((uint64_t)buf[offset+1]) << 0x30)
	     | (((uint64_t)buf[offset+2]) << 0x28)
	     | (((uint64_t)buf[offset+3]) << 0x20)
	     | (((uint64_t)buf[offset+4]) << 0x18)
	     | (((uint64_t)buf[offset+5]) << 0x10)
	     | (((uint64_t)buf[offset+6]) <<    8)
	     | (((uint64_t)buf[offset+7]) <<    0);
}

#define upk_u8le(buf, offset)  upk_u8(buf, offset)

static inline
uint16_t upk_u16le(const void * const bufp, const int offset)
{
	const uint8_t * const buf = bufp;
	return (((uint16_t)buf[offset+0]) <<    0)
	     | (((uint16_t)buf[offset+1]) <<    8);
}

static inline
uint32_t upk_u32le(const void * const bufp, const int offset)
{
	const uint8_t * const buf = bufp;
	return (((uint32_t)buf[offset+0]) <<    0)
	     | (((uint32_t)buf[offset+1]) <<    8)
	     | (((uint32_t)buf[offset+2]) << 0x10)
	     | (((uint32_t)buf[offset+3]) << 0x18);
}

static inline
uint64_t upk_u64le(const void * const bufp, const int offset)
{
	const uint8_t * const buf = bufp;
	return (((uint64_t)buf[offset+0]) <<    0)
	     | (((uint64_t)buf[offset+1]) <<    8)
	     | (((uint64_t)buf[offset+2]) << 0x10)
	     | (((uint64_t)buf[offset+3]) << 0x18)
	     | (((uint64_t)buf[offset+4]) << 0x20)
	     | (((uint64_t)buf[offset+5]) << 0x28)
	     | (((uint64_t)buf[offset+6]) << 0x30)
	     | (((uint64_t)buf[offset+7]) << 0x38);
}


static inline
void pk_u8(void * const bufp, const int offset, const uint8_t nv)
{
	uint8_t * const buf = bufp;
	buf[offset] = nv;
}

#define pk_u8be(buf, offset, nv)  pk_u8(buf, offset, nv)

static inline
void pk_u16be(void * const bufp, const int offset, const uint16_t nv)
{
	uint8_t * const buf = bufp;
	buf[offset+0] = (nv >>    8) & 0xff;
	buf[offset+1] = (nv >>    0) & 0xff;
}

static inline
void pk_u32be(void * const bufp, const int offset, const uint32_t nv)
{
	uint8_t * const buf = bufp;
	buf[offset+0] = (nv >> 0x18) & 0xff;
	buf[offset+1] = (nv >> 0x10) & 0xff;
	buf[offset+2] = (nv >>    8) & 0xff;
	buf[offset+3] = (nv >>    0) & 0xff;
}

static inline
void pk_u64be(void * const bufp, const int offset, const uint64_t nv)
{
	uint8_t * const buf = bufp;
	buf[offset+0] = (nv >> 0x38) & 0xff;
	buf[offset+1] = (nv >> 0x30) & 0xff;
	buf[offset+2] = (nv >> 0x28) & 0xff;
	buf[offset+3] = (nv >> 0x20) & 0xff;
	buf[offset+4] = (nv >> 0x18) & 0xff;
	buf[offset+5] = (nv >> 0x10) & 0xff;
	buf[offset+6] = (nv >>    8) & 0xff;
	buf[offset+7] = (nv >>    0) & 0xff;
}

#define pk_u8le(buf, offset, nv)  pk_u8(buf, offset, nv)

static inline
void pk_u16le(void * const bufp, const int offset, const uint16_t nv)
{
	uint8_t * const buf = bufp;
	buf[offset+0] = (nv >>    0) & 0xff;
	buf[offset+1] = (nv >>    8) & 0xff;
}

static inline
void pk_u32le(void * const bufp, const int offset, const uint32_t nv)
{
	uint8_t * const buf = bufp;
	buf[offset+0] = (nv >>    0) & 0xff;
	buf[offset+1] = (nv >>    8) & 0xff;
	buf[offset+2] = (nv >> 0x10) & 0xff;
	buf[offset+3] = (nv >> 0x18) & 0xff;
}

static inline
void pk_u64le(void * const bufp, const int offset, const uint64_t nv)
{
	uint8_t * const buf = bufp;
	buf[offset+0] = (nv >>    0) & 0xff;
	buf[offset+1] = (nv >>    8) & 0xff;
	buf[offset+2] = (nv >> 0x10) & 0xff;
	buf[offset+3] = (nv >> 0x18) & 0xff;
	buf[offset+4] = (nv >> 0x20) & 0xff;
	buf[offset+5] = (nv >> 0x28) & 0xff;
	buf[offset+6] = (nv >> 0x30) & 0xff;
	buf[offset+7] = (nv >> 0x38) & 0xff;
}

extern void bin2hex(char *, const void *, size_t);

#define _SNP2(fn, ...)  do{  \
        int __n42 = fn(s, sz, __VA_ARGS__);  \
        s += __n42;  \
        sz = (sz <= __n42) ? 0 : (sz - __n42);  \
        rv += __n42;  \
}while(0)

#define _SNP(...)  _SNP2(snprintf, __VA_ARGS__)

#endif
