#include "tex_decode.h"
#include <string.h>

#define PX(a,r,g,b) (((uint32_t)(a)<<24)|((uint32_t)(r)<<16)|((uint32_t)(g)<<8)|(uint32_t)(b))

uint32_t tex_bpp(uint32_t f){
    switch(GCM_TEX_FMT(f)){
    case 0x81: return 1;
    case 0x82: case 0x83: case 0x84: case 0x97: case 0x9d:
    case 0x8b: case 0x8f: case 0x92: case 0x93: case 0x94: return 2;
    case 0x85: case 0x90: case 0x91: case 0x9e: case 0x95: case 0x9f:
    case 0x9c: return 4;
    case 0x9a: return 8;
    case 0x9b: return 16;
    case 0x86: return 8;
    case 0x87: case 0x88: return 16;
    default: return 4;
    }
}
int tex_is_dxt(uint32_t f){
    uint32_t x=GCM_TEX_FMT(f);
    return x==0x86||x==0x87||x==0x88;
}

static uint32_t morton(uint32_t x, uint32_t y, uint32_t w, uint32_t h){
    uint32_t off=0, sh=0;
    while(w>1||h>1){
        if(w>1){ off|=(x&1)<<sh; x>>=1; sh++; w>>=1; }
        if(h>1){ off|=(y&1)<<sh; y>>=1; sh++; h>>=1; }
    }
    return off;
}

static float half2f(uint16_t hv){
    uint32_t s=(hv>>15)&1,e=(hv>>10)&0x1f,f=hv&0x3ff,bits;
    if(e==0){ if(!f) bits=s<<31;
        else { e=113; while(!(f&0x400)){ f<<=1; e--; } f&=0x3ff;
               bits=(s<<31)|(e<<23)|(f<<13); } }
    else if(e==31) bits=(s<<31)|0x7f800000|(f<<13);
    else bits=(s<<31)|((e+112)<<23)|(f<<13);
    float r; memcpy(&r,&bits,4); return r;
}
static uint8_t f2u8(float f){
    if(f<=0) return 0; if(f>=1) return 255;
    return (uint8_t)(f*255.0f+0.5f);
}

static uint32_t texel(const uint8_t* p, uint32_t fmt){
    switch(fmt){
    case 0x81:{ uint8_t v=p[0]; return PX(v,v,v,v); }
    case 0x85: return PX(p[0],p[1],p[2],p[3]);
    case 0x9e: return PX(0xff,p[1],p[2],p[3]);
    case 0x84:{ uint32_t v=(p[0]<<8)|p[1];
        uint32_t r=(v>>11)&31,g=(v>>5)&63,b=v&31;
        return PX(0xff,(r<<3)|(r>>2),(g<<2)|(g>>4),(b<<3)|(b>>2)); }
    case 0x82: case 0x9d:{ uint32_t v=(p[0]<<8)|p[1];
        uint32_t a=(fmt==0x82)?((v&0x8000)?0xff:0):0xff;
        uint32_t r=(v>>10)&31,g=(v>>5)&31,b=v&31;
        return PX(a,(r<<3)|(r>>2),(g<<3)|(g>>2),(b<<3)|(b>>2)); }
    case 0x83:{ uint32_t v=(p[0]<<8)|p[1];
        uint32_t a=(v>>12)&15,r=(v>>8)&15,g=(v>>4)&15,b=v&15;
        return PX(a*17,r*17,g*17,b*17); }
    case 0x97:{ uint32_t v=(p[0]<<8)|p[1];
        uint32_t r=(v>>11)&31,g=(v>>6)&31,b=(v>>1)&31,a=(v&1)?0xff:0;
        return PX(a,(r<<3)|(r>>2),(g<<3)|(g>>2),(b<<3)|(b>>2)); }
    case 0x8b:{ uint8_t g=p[0],b=p[1];
        return PX(g,b,g,b); }
    case 0x8f:{ uint32_t v=(p[0]<<8)|p[1];
        uint32_t r=(v>>10)&63,g=(v>>5)&31,b=v&31;
        return PX(0xff,(r<<2)|(r>>4),(g<<3)|(g>>2),(b<<3)|(b>>2)); }
    case 0x92: case 0x93:{ uint32_t v=(p[0]<<8)|p[1];
        uint8_t d=(uint8_t)(v>>8); return PX(0xff,d,d,d); }
    case 0x90: case 0x91:{ uint32_t v=((uint32_t)p[0]<<24)|(p[1]<<16)|(p[2]<<8)|p[3];
        uint8_t d=(uint8_t)(v>>24); return PX(0xff,d,d,d); }
    case 0x94:{ uint32_t v=(p[0]<<8)|p[1];
        uint8_t x=(uint8_t)(v>>8); return PX(0xff,x,x,x); }
    case 0x95:{ uint32_t y=(p[0]<<8)|p[1], x=(p[2]<<8)|p[3];
        return PX(0xff,(uint8_t)(y>>8),(uint8_t)(x>>8),0); }
    case 0x9f:{ float y=half2f((uint16_t)((p[0]<<8)|p[1]));
        float x=half2f((uint16_t)((p[2]<<8)|p[3]));
        return PX(0xff,f2u8(y),f2u8(x),0); }
    case 0x9a:{
        float w=half2f((uint16_t)((p[0]<<8)|p[1]));
        float z=half2f((uint16_t)((p[2]<<8)|p[3]));
        float y=half2f((uint16_t)((p[4]<<8)|p[5]));
        float x=half2f((uint16_t)((p[6]<<8)|p[7]));
        return PX(f2u8(w),f2u8(x),f2u8(y),f2u8(z)); }
    case 0x9c:{ uint32_t u=((uint32_t)p[0]<<24)|(p[1]<<16)|(p[2]<<8)|p[3];
        float f; memcpy(&f,&u,4); uint8_t v=f2u8(f); return PX(0xff,v,v,v); }
    case 0x9b:{ float c[4];
        for(int i=0;i<4;i++){ uint32_t u=((uint32_t)p[i*4]<<24)|(p[i*4+1]<<16)|
                                          (p[i*4+2]<<8)|p[i*4+3];
            memcpy(&c[i],&u,4); }
        return PX(f2u8(c[0]),f2u8(c[3]),f2u8(c[2]),f2u8(c[1])); }
    default: return 0xffff00ffu;
    }
}

static void dxt_colors(const uint8_t* b, uint32_t c[4], int dxt1){
    uint16_t c0=b[0]|(b[1]<<8), c1=b[2]|(b[3]<<8);
    uint32_t r0=(c0>>11)&31,g0=(c0>>5)&63,b0=c0&31;
    uint32_t r1=(c1>>11)&31,g1=(c1>>5)&63,b1=c1&31;
    uint32_t R0=(r0<<3)|(r0>>2),G0=(g0<<2)|(g0>>4),B0=(b0<<3)|(b0>>2);
    uint32_t R1=(r1<<3)|(r1>>2),G1=(g1<<2)|(g1>>4),B1=(b1<<3)|(b1>>2);
    c[0]=PX(0xff,R0,G0,B0); c[1]=PX(0xff,R1,G1,B1);
    if(!dxt1||c0>c1){
        c[2]=PX(0xff,(2*R0+R1)/3,(2*G0+G1)/3,(2*B0+B1)/3);
        c[3]=PX(0xff,(R0+2*R1)/3,(G0+2*G1)/3,(B0+2*B1)/3);
    } else {
        c[2]=PX(0xff,(R0+R1)/2,(G0+G1)/2,(B0+B1)/2);
        c[3]=0;
    }
}
static void decode_dxt(const uint8_t* src, uint32_t* dst,
                       uint32_t fmt, uint32_t w, uint32_t h){
    uint32_t bw=(w+3)/4, bh=(h+3)/4;
    uint32_t bsz=(fmt==0x86)?8:16;
    for(uint32_t by=0;by<bh;by++) for(uint32_t bx=0;bx<bw;bx++){
        const uint8_t* b=src+(by*bw+bx)*bsz;
        uint32_t cols[4];
        const uint8_t* cb=(fmt==0x86)?b:b+8;
        dxt_colors(cb,cols,fmt==0x86);
        uint32_t bits=cb[4]|(cb[5]<<8)|(cb[6]<<16)|((uint32_t)cb[7]<<24);
        uint8_t alpha[16];
        if(fmt==0x87){
            for(int i=0;i<16;i++){
                uint8_t v=(b[i/2]>>((i&1)*4))&15; alpha[i]=v*17; }
        } else if(fmt==0x88){
            uint8_t a0=b[0],a1=b[1];
            uint64_t ab=0;
            for(int i=0;i<6;i++) ab|=(uint64_t)b[2+i]<<(i*8);
            for(int i=0;i<16;i++){
                uint8_t code=(ab>>(i*3))&7;
                if(code==0) alpha[i]=a0;
                else if(code==1) alpha[i]=a1;
                else if(a0>a1) alpha[i]=(uint8_t)(((8-code)*a0+(code-1)*a1)/7);
                else if(code==6) alpha[i]=0;
                else if(code==7) alpha[i]=255;
                else alpha[i]=(uint8_t)(((6-code)*a0+(code-1)*a1)/5);
            }
        }
        for(uint32_t py=0;py<4;py++) for(uint32_t px=0;px<4;px++){
            uint32_t x=bx*4+px, y=by*4+py;
            if(x>=w||y>=h) continue;
            uint32_t c=cols[(bits>>((py*4+px)*2))&3];
            if(fmt!=0x86) c=(c&0x00ffffffu)|((uint32_t)alpha[py*4+px]<<24);
            dst[y*w+x]=c;
        }
    }
}

int tex_decode_level(const uint8_t* src, uint32_t* dst,
                     uint32_t fmt_byte, uint32_t w, uint32_t h, uint32_t pitch){
    uint32_t fmt=GCM_TEX_FMT(fmt_byte);
    if(tex_is_dxt(fmt_byte)){ decode_dxt(src,dst,fmt,w,h); return 1; }
    uint32_t bpp=tex_bpp(fmt_byte);
    int linear=GCM_TEX_LN(fmt_byte);
    switch(fmt){
    case 0x81: case 0x82: case 0x83: case 0x84: case 0x85: case 0x8b:
    case 0x8f: case 0x90: case 0x91: case 0x92: case 0x93: case 0x94:
    case 0x95: case 0x97: case 0x9a: case 0x9b: case 0x9c: case 0x9d:
    case 0x9e: case 0x9f:
        break;
    default:
        return 0;
    }
    if(linear){
        for(uint32_t y=0;y<h;y++)
            for(uint32_t x=0;x<w;x++)
                dst[y*w+x]=texel(src+y*pitch+x*bpp,fmt);
    } else {
        for(uint32_t y=0;y<h;y++)
            for(uint32_t x=0;x<w;x++)
                dst[y*w+x]=texel(src+morton(x,y,w,h)*bpp,fmt);
    }
    return 1;
}

uint32_t tex_level_bytes(uint32_t fmt, uint32_t w, uint32_t h,
                         uint32_t d, uint32_t pitch){
    if(!d) d=1;
    uint32_t sz;
    if(tex_is_dxt(fmt))
        sz = (GCM_TEX_LN(fmt)&&pitch) ? ((h+3)/4)*pitch
                                      : ((w+3)/4)*((h+3)/4)*tex_bpp(fmt);
    else if(GCM_TEX_LN(fmt)) sz = h*(pitch?pitch:w*tex_bpp(fmt));
    else                     sz = w*h*tex_bpp(fmt);
    return sz*d;
}
static uint32_t chain_bytes(uint32_t fmt, uint32_t w, uint32_t h, uint32_t d,
                            uint32_t nmip, uint32_t pitch){
    uint32_t total=0, lw=w, lh=h, ld=d?d:1;
    if(!nmip) nmip=1;
    for(uint32_t l=0;l<nmip;l++){
        total+=tex_level_bytes(fmt,lw,lh,ld,pitch);
        if(lw>1) lw>>=1;
        if(lh>1) lh>>=1;
        if(ld>1) ld>>=1;
    }
    return total;
}
uint32_t tex_cube_face_stride(uint32_t fmt, uint32_t w, uint32_t h,
                              uint32_t nmip, uint32_t pitch){
    uint32_t total=chain_bytes(fmt,w,h,1,nmip,pitch);
    if(!GCM_TEX_LN(fmt)) total=(total+127u)&~127u;
    return total;
}
uint32_t tex_total_bytes(uint32_t fmt, uint32_t w, uint32_t h, uint32_t d,
                         uint32_t nmip, int cube, uint32_t pitch){
    uint32_t chain=chain_bytes(fmt,w,h,d,nmip,pitch);
    if(!cube) return chain;
    return 5u*tex_cube_face_stride(fmt,w,h,nmip,pitch)+chain;
}
