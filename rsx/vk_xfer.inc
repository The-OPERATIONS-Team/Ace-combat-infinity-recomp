static Surf* surf_find(uint32_t ea, uint32_t w, uint32_t h, uint32_t* off_out){
    Surf* best=0;
    if(off_out) *off_out=0;
    for(int sl=g_surfhead[surf_hkey(ea)]; sl; sl=g_surf[sl-1].hnext){
        Surf* c2=&g_surf[sl-1];
        if(!c2->img||!c2->inited||c2->ea!=ea) continue;
        if(w&&h&&c2->w==w&&c2->h==h){ c2->last_frame=g_frame; return c2; }
        if(!best||c2->last_frame>best->last_frame) best=c2;
    }
    if(best){ best->last_frame=g_frame; return best; }
    for(int i=0;i<NSURF;i++){
        Surf* c2=&g_surf[i];
        if(!c2->img||!c2->inited) continue;
        uint64_t span=(uint64_t)c2->w*c2->h*4;
        if(ea>=c2->ea&&ea<c2->ea+span){
            if(!best||c2->last_frame>best->last_frame) best=c2;
        }
    }
    if(best){
        if(off_out) *off_out=ea-best->ea;
        best->last_frame=g_frame;
    }
    return best;
}

static void surf_to_layout(Surf* s, int want){
    if(s->layout==want) return;
    rp_end(); cmd_begin();
    VkImageLayout from = s->layout==1?VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL
                       : s->layout==2?VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL
                       : VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL;
    VkImageLayout to = want==0?VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL
                              :VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL;
    VkImageMemoryBarrier b={.sType=VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,
        .srcAccessMask=VK_ACCESS_MEMORY_WRITE_BIT,
        .dstAccessMask=VK_ACCESS_MEMORY_READ_BIT|VK_ACCESS_MEMORY_WRITE_BIT,
        .oldLayout=from,.newLayout=to,
        .srcQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
        .dstQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
        .image=s->img,.subresourceRange={VK_IMAGE_ASPECT_COLOR_BIT,0,1,0,1}};
    vkCmdPipelineBarrier(g_cmd,stages_for(b.srcAccessMask,1),
            stages_for(b.dstAccessMask,0),0,0,0,0,0,1,&b);
    s->layout=want;
}

static VkImageLayout surf_layout_enum(Surf* s){
    if(!s->inited) return VK_IMAGE_LAYOUT_UNDEFINED;
    return s->layout==1?VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL
         : s->layout==2?VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL
         : VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL;
}

static void surf_to_dst(Surf* ds){
    rp_end(); cmd_begin();
    VkImageMemoryBarrier b={.sType=VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,
        .srcAccessMask=VK_ACCESS_MEMORY_WRITE_BIT,
        .dstAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT,
        .oldLayout=surf_layout_enum(ds),
        .newLayout=VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
        .srcQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
        .dstQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
        .image=ds->img,.subresourceRange={VK_IMAGE_ASPECT_COLOR_BIT,0,1,0,1}};
    vkCmdPipelineBarrier(g_cmd,stages_for(b.srcAccessMask,1),
            stages_for(b.dstAccessMask,0),0,0,0,0,0,1,&b);
}
static void surf_dst_done(Surf* ds){
    VkImageMemoryBarrier b={.sType=VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,
        .srcAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT,
        .dstAccessMask=VK_ACCESS_MEMORY_READ_BIT,
        .oldLayout=VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
        .newLayout=VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL,
        .srcQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
        .dstQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
        .image=ds->img,.subresourceRange={VK_IMAGE_ASPECT_COLOR_BIT,0,1,0,1}};
    vkCmdPipelineBarrier(g_cmd,stages_for(b.srcAccessMask,1),
            stages_for(b.dstAccessMask,0),0,0,0,0,0,1,&b);
    ds->inited=1; ds->layout=0;
}

static void rsxd_m2m_inner(void){
    uint32_t sloc=dma_loc(g_rsx.m2m.dma_in), dloc=dma_loc(g_rsx.m2m.dma_out);
    uint32_t sea=resolve(g_rsx.m2m.off_in,sloc), dea=resolve(g_rsx.m2m.off_out,dloc);
    uint32_t nbytes=g_rsx.m2m.line_len, rows=g_rsx.m2m.line_cnt;
    if(!sea||!dea||!nbytes||!rows) return;
    uint32_t spitch=g_rsx.m2m.pitch_in?g_rsx.m2m.pitch_in:nbytes;
    uint32_t dpitch=g_rsx.m2m.pitch_out?g_rsx.m2m.pitch_out:nbytes;

    if(g_up>0){
        uint32_t soff=0;
        Surf* ss=surf_find(sea,0,0,&soff);
        if(ss){
            uint32_t w=nbytes/4, h=rows;
            uint32_t sx=0, sy=0;
            if(soff){ uint32_t sp=ss->w*4; sy=soff/sp; sx=(soff%sp)/4; }
            if(sx+w>ss->w) w=(sx<ss->w)?ss->w-sx:0;
            if(sy+h>ss->h) h=(sy<ss->h)?ss->h-sy:0;
            if(w&&h&&w<=4096&&h<=4096){
                Surf* ds=surf_get(dea,nbytes/4,rows);
                if(ds&&ds!=ss&&ds->isf==ss->isf){
                    surf_to_layout(ss,2);
                    surf_to_dst(ds);
                    VkImageCopy ic={.srcSubresource={VK_IMAGE_ASPECT_COLOR_BIT,0,0,1},
                        .srcOffset={(int32_t)sx,(int32_t)sy,0},
                        .dstSubresource={VK_IMAGE_ASPECT_COLOR_BIT,0,0,1},
                        .extent={w,h,1}};
                    vkCmdCopyImage(g_cmd,ss->img,VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
                        ds->img,VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,1,&ic);
                    surf_dst_done(ds);
                    { static long mn; if(++mn<=24)
                        fprintf(stderr,"[RSXD] m2m GPU 0x%x+0x%x -> 0x%x %ux%u\n",
                                ss->ea,soff,dea,w,h); }
                    return;
                }
            }
        }
    }
    for(uint32_t y=0;y<rows;y++)
        memmove(g_base+dea+(size_t)y*dpitch,g_base+sea+(size_t)y*spitch,nbytes);
    { static long mn2; if(++mn2<=16)
        fprintf(stderr,"[RSXD] m2m CPU 0x%x -> 0x%x %ub x%u\n",sea,dea,nbytes,rows); }
}

typedef struct { uint32_t sea, sw, sh;
                 uint32_t dea, ox, oy, ow, oh, pitch; } Writeback;
static Writeback g_wb[16];
static int g_nwb;

static Surf* surf_exact(uint32_t ea, uint32_t w, uint32_t h){
    for(int sl=g_surfhead[surf_hkey(ea)]; sl; sl=g_surf[sl-1].hnext){
        Surf* c2=&g_surf[sl-1];
        if(c2->img&&c2->inited&&c2->ea==ea&&c2->w==w&&c2->h==h){
            c2->last_frame=g_frame; return c2; }
    }
    return 0;
}

static void wb_flush(void){
    if(!g_nwb) return;
    uint32_t off=g_toff;
    rp_end(); cmd_begin();
    int n=0;
    uint32_t offs[16];
    for(int i=0;i<16;i++) offs[i]=0xffffffffu;
    for(int i=0;i<g_nwb;i++){
        Writeback* w=&g_wb[i];
        uint32_t need=w->ow*w->oh*4;
        if(off+need>TBUF_CAP) break;
        Surf* s=surf_exact(w->sea,w->sw,w->sh);
        if(!s){ static int wn; if(wn++<8)
            fprintf(stderr,"[RSXD] writeback source 0x%x %ux%u no longer resident "
                    "- dropped (dst 0x%x)\n",w->sea,w->sw,w->sh,w->dea);
            continue; }
        surf_to_layout(s,2);
        VkBufferImageCopy bc={.bufferOffset=off,
            .imageSubresource={VK_IMAGE_ASPECT_COLOR_BIT,0,0,1},
            .imageOffset={(int32_t)w->ox,(int32_t)w->oy,0},
            .imageExtent={w->ow,w->oh,1}};
        vkCmdCopyImageToBuffer(g_cmd,s->img,VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
            g_tbuf,1,&bc);
        offs[i]=off; off+=need; n++;
    }
    if(!n){ g_nwb=0; return; }
    cmd_submit();
    for(int i=0;i<g_nwb;i++){
        Writeback* w=&g_wb[i];
        if(offs[i]==0xffffffffu) continue;
        const uint8_t* sp2=g_tptr+offs[i];
        for(uint32_t y=0;y<w->oh;y++){
            uint8_t* dr=g_base+w->dea+(size_t)y*w->pitch;
            const uint8_t* srr=sp2+(size_t)y*w->ow*4;
            for(uint32_t x=0;x<w->ow;x++){
                dr[x*4+0]=srr[x*4+3]; dr[x*4+1]=srr[x*4+2];
                dr[x*4+2]=srr[x*4+1]; dr[x*4+3]=srr[x*4+0];
            }
        }
    }
    g_nwb=0;
}

static void rsxd_blit_inner(void){
    if(!draw_up()) return;
    uint32_t sloc=dma_loc(g_rsx.blit.src_dma);
    uint32_t sea=resolve(g_rsx.blit.in_off,sloc);
    uint32_t dloc=dma_loc(g_rsx.s2d.dst_dma);
    uint32_t dea=resolve(g_rsx.s2d.off_dst,dloc);
    uint32_t sw=g_rsx.blit.in_sz&0xffff,  sh=(g_rsx.blit.in_sz>>16)&0xffff;
    uint32_t ow=g_rsx.blit.out_sz&0xffff, oh=(g_rsx.blit.out_sz>>16)&0xffff;
    uint32_t ox=g_rsx.blit.out_pt&0xffff, oy=(g_rsx.blit.out_pt>>16)&0xffff;
    if(!sea||!dea||!sw||!sh||!ow||!oh) return;
    if(sw>4096||sh>4096||ow>4096||oh>4096) return;
    uint32_t soff=0;
    Surf* ss=surf_find(sea,sw,sh,&soff);
    if(!ss){ static int wn; if(wn++<8)
        fprintf(stderr,"[RSXD] blit src 0x%x not GPU-resident - CPU path TODO\n",sea);
        return; }
    uint32_t dpitch=(g_rsx.s2d.pitch>>16)&0xffff;
    Surf* ds=0;
    for(int i=0;i<NSURF;i++){
        Surf* c2=&g_surf[i];
        if(!c2->img||c2->isf) continue;
        uint64_t span=(uint64_t)c2->w*c2->h*4;
        if(dea<c2->ea||dea>=c2->ea+span) continue;
        uint32_t off=dea-c2->ea, rowb=c2->w*4;
        uint32_t col=(off%rowb)/4, row=off/rowb;
        if(dpitch&&c2->w*4!=dpitch) continue;
        if(col+ox+ow<=c2->w&&row+oy+oh<=c2->h){ ds=c2; ox+=col; oy+=row; break; }
    }
    if(!ds){
        uint32_t dw=(dpitch&&dpitch/4>=ox+ow)?dpitch/4:(ox+ow);
        ds=surf_get(dea,dw,oy+oh);
    }
    if(!ds||ds==ss) return;
    uint32_t sx=0, sy=0;
    if(soff){ uint32_t sp=ss->w*4; sy=soff/sp; sx=(soff%sp)/4; }
    if(sx+sw>ss->w) sw=(sx<ss->w)?ss->w-sx:0;
    if(sy+sh>ss->h) sh=(sy<ss->h)?ss->h-sy:0;
    if(!sw||!sh) return;
    surf_to_layout(ss,2);
    surf_to_dst(ds);
    VkImageBlit ib={.srcSubresource={VK_IMAGE_ASPECT_COLOR_BIT,0,0,1},
        .srcOffsets={{(int32_t)sx,(int32_t)sy,0},
                     {(int32_t)(sx+sw),(int32_t)(sy+sh),1}},
        .dstSubresource={VK_IMAGE_ASPECT_COLOR_BIT,0,0,1},
        .dstOffsets={{(int32_t)ox,(int32_t)oy,0},
                     {(int32_t)(ox+ow),(int32_t)(oy+oh),1}}};
    vkCmdBlitImage(g_cmd,ss->img,VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
        ds->img,VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,1,&ib,VK_FILTER_LINEAR);
    surf_dst_done(ds);
    if(!ds->isf){
        uint32_t dpitch=(g_rsx.s2d.pitch>>16)&0xffff;
        if(!dpitch) dpitch=ds->w*4;
        int slot=-1;
        for(int i=0;i<g_nwb;i++) if(g_wb[i].dea==dea){ slot=i; break; }
        if(slot<0&&g_nwb<(int)(sizeof g_wb/sizeof g_wb[0])) slot=g_nwb++;
        if(slot>=0)
            g_wb[slot]=(Writeback){.sea=ds->ea,.sw=ds->w,.sh=ds->h,
                                   .dea=dea,.ox=ox,.oy=oy,
                                   .ow=ow,.oh=oh,.pitch=dpitch};
    }
    { static long bn; if(++bn<=24)
        fprintf(stderr,"[RSXD] blit GPU 0x%x(%ux%u) -> 0x%x(%u,%u %ux%u)\n",
                ss->ea,sw,sh,dea,ox,oy,ow,oh); }
}
