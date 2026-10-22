#include "rsx.h"
#include "vk_present.h"
#include "vk_draw.h"
#include "capture.h"
#include <stdio.h>

static uint8_t*  g_base;
static uint32_t  g_local_ea, g_local_size;
static uint64_t  g_mem_size;
static uint32_t (*g_ioff2ea)(uint32_t);

typedef RsxDispBufCap RsxDispBuf;
static RsxDispBuf g_disp[8];

void rsx_init(uint8_t* base, uint32_t local_ea, uint32_t local_size,
              uint32_t (*ioff2ea)(uint32_t), uint64_t mem_size){
    g_base=base; g_local_ea=local_ea; g_local_size=local_size; g_ioff2ea=ioff2ea;
    g_mem_size=mem_size;
    rsxd_init(base,local_ea,local_size,ioff2ea,mem_size);
    fprintf(stderr,"[RSX] init base=%p local=0x%x+0x%x\n",(void*)base,local_ea,local_size);
}

void rsx_set_display_buffer(uint32_t id, uint32_t offset, uint32_t pitch,
                            uint32_t width, uint32_t height){
    if(id>=8) return;
    g_disp[id].valid=1; g_disp[id].offset=offset; g_disp[id].pitch=pitch;
    g_disp[id].width=width; g_disp[id].height=height;
    cap_setdisp(id,offset,pitch,width,height);
    fprintf(stderr,"[RSX] display buffer id=%u off=0x%x pitch=%u %ux%u\n",
            id,offset,pitch,width,height);
}

void rsx_sync_read(uint32_t ea, uint32_t size){ (void)ea; (void)size; }

void rsx_decode_frame_mark(void);

void rsx_flip(uint32_t bufid){
    cap_flip(bufid);
    cap_maybe_start(g_base,g_mem_size,g_local_ea,g_local_size,g_ioff2ea,g_disp);
    rsx_decode_frame_mark();
    static int vk_ok=-1;
    if(vk_ok<0) vk_ok=rsxvk_init();
    if(!vk_ok) return;
    if(bufid>=8||!g_disp[bufid].valid){
        int found=-1;
        for(int i=0;i<8;i++) if(g_disp[i].valid){ found=i; break; }
        if(found<0) return;
        bufid=(uint32_t)found;
    }
    RsxDispBuf* d=&g_disp[bufid];
    if((uint64_t)d->offset+(uint64_t)d->pitch*d->height>g_local_size) return;
    if(!d->width||!d->height||!d->pitch) return;
    if(rsxd_flip_present(g_local_ea+d->offset,d->width,d->height)) return;
    rsxvk_present(g_base+g_local_ea+d->offset,d->width,d->height,d->pitch);
}
