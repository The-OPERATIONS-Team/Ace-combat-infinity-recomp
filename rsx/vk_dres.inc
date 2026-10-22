int dres_vs(uint32_t*,int);
int dres_fs(uint32_t*,int,int);

static VkPipeline g_dres_pipe[3];
static VkSampler  g_dres_samp;

static int dres_init(int mode){
    if(g_dres_pipe[mode]) return 1;
    static uint32_t vs[16384], fs[16384];
    int nvs=dres_vs(vs,16384), nfs=dres_fs(fs,16384,mode);
    if(!nvs||!nfs) return 0;
    VkShaderModule vm=make_module(vs,nvs), fm=make_module(fs,nfs);
    if(!vm||!fm) return 0;
    VkPipelineShaderStageCreateInfo stg[2]={
        {.sType=VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO,
         .stage=VK_SHADER_STAGE_VERTEX_BIT,.module=vm,.pName="main"},
        {.sType=VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO,
         .stage=VK_SHADER_STAGE_FRAGMENT_BIT,.module=fm,.pName="main"}};
    VkPipelineVertexInputStateCreateInfo vin={
        .sType=VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO};
    VkPipelineInputAssemblyStateCreateInfo ia={
        .sType=VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO,
        .topology=VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST};
    VkPipelineViewportStateCreateInfo vp={
        .sType=VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO,
        .viewportCount=1,.scissorCount=1};
    VkPipelineRasterizationStateCreateInfo rs={
        .sType=VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO,
        .polygonMode=VK_POLYGON_MODE_FILL,.cullMode=VK_CULL_MODE_NONE,
        .frontFace=VK_FRONT_FACE_COUNTER_CLOCKWISE,.lineWidth=1.0f};
    VkPipelineMultisampleStateCreateInfo ms={
        .sType=VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO,
        .rasterizationSamples=VK_SAMPLE_COUNT_1_BIT};
    VkPipelineDepthStencilStateCreateInfo ds={
        .sType=VK_STRUCTURE_TYPE_PIPELINE_DEPTH_STENCIL_STATE_CREATE_INFO};
    VkPipelineColorBlendAttachmentState ba={.colorWriteMask=0xf};
    VkPipelineColorBlendStateCreateInfo cb={
        .sType=VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO,
        .attachmentCount=1,.pAttachments=&ba};
    VkDynamicState dyn[2]={VK_DYNAMIC_STATE_VIEWPORT,VK_DYNAMIC_STATE_SCISSOR};
    VkPipelineDynamicStateCreateInfo dst={
        .sType=VK_STRUCTURE_TYPE_PIPELINE_DYNAMIC_STATE_CREATE_INFO,
        .dynamicStateCount=2,.pDynamicStates=dyn};
    VkGraphicsPipelineCreateInfo pci={
        .sType=VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO,
        .stageCount=2,.pStages=stg,.pVertexInputState=&vin,
        .pInputAssemblyState=&ia,.pViewportState=&vp,.pRasterizationState=&rs,
        .pMultisampleState=&ms,.pDepthStencilState=&ds,.pColorBlendState=&cb,
        .pDynamicState=&dst,.layout=g_playout,.renderPass=g_rp,.subpass=0};
    VkResult r=vkCreateGraphicsPipelines(g_dev,VK_NULL_HANDLE,1,&pci,NULL,
                                         &g_dres_pipe[mode]);
    vkDestroyShaderModule(g_dev,vm,NULL); vkDestroyShaderModule(g_dev,fm,NULL);
    if(r){ fprintf(stderr,"[RSXD] dres pipeline -> %d\n",(int)r); return 0; }
    if(g_dres_samp) return 1;
    VkSamplerCreateInfo sci={.sType=VK_STRUCTURE_TYPE_SAMPLER_CREATE_INFO,
        .magFilter=VK_FILTER_NEAREST,.minFilter=VK_FILTER_NEAREST,
        .mipmapMode=VK_SAMPLER_MIPMAP_MODE_NEAREST,
        .addressModeU=VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_EDGE,
        .addressModeV=VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_EDGE,
        .addressModeW=VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_EDGE};
    if(vkCreateSampler(g_dev,&sci,NULL,&g_dres_samp)) return 0;
    fprintf(stderr,"[RSXD] depth-resolve pipeline up\n");
    return 1;
}

static Surf* dres_find(uint32_t zea, uint32_t w, uint32_t h);

static VkImageView dres_atlas(uint32_t ea, uint32_t w, uint32_t h,
                              Surf* first, uint32_t nband, int mode){
    if(!dres_init(mode)) return 0;
    Surf* dst=surf_get(ea,w,h);
    if(!dst) return 0;
    uint32_t bh=first->h;
    uint32_t zp=first->zpitch?first->zpitch:first->w*4u;
    Surf* band[8]; VkDescriptorSet dset[8];
    for(uint32_t i=0;i<nband&&i<8;i++){
        band[i]=i?dres_find(ea+i*zp*bh,first->w,bh):first;
        if(band[i]==dst) band[i]=0;
        dset[i]=VK_NULL_HANDLE;
    }
    rp_end(); cmd_begin();
    VkImageMemoryBarrier zb={.sType=VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,
        .srcAccessMask=VK_ACCESS_DEPTH_STENCIL_ATTACHMENT_WRITE_BIT,
        .dstAccessMask=VK_ACCESS_SHADER_READ_BIT,
        .oldLayout=VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL,
        .newLayout=VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL,
        .srcQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
        .dstQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
        .subresourceRange={VK_IMAGE_ASPECT_DEPTH_BIT,0,1,0,1}};
    VkDescriptorImageInfo zi[8], wi={.sampler=g_sampler,.imageView=g_white_view,
        .imageLayout=VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL};
    VkDescriptorBufferInfo bi={.buffer=g_ubuf,.offset=0,.range=468*16};
    for(uint32_t i=0;i<nband;i++){
        if(!band[i]) continue;
        zb.image=band[i]->z;
        vkCmdPipelineBarrier(g_cmd,stages_for(zb.srcAccessMask,1),
            stages_for(zb.dstAccessMask,0),0,0,0,0,0,1,&zb);
        VkDescriptorSetAllocateInfo dai={
            .sType=VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO,
            .descriptorPool=g_dpool,.descriptorSetCount=1,.pSetLayouts=&g_dsl};
        if(vkAllocateDescriptorSets(g_dev,&dai,&dset[i])){ dset[i]=VK_NULL_HANDLE; continue; }
        zi[i]=(VkDescriptorImageInfo){.sampler=g_dres_samp,
            .imageView=band[i]->zview,
            .imageLayout=VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL};
        VkWriteDescriptorSet wr[21];
        wr[0]=(VkWriteDescriptorSet){.sType=VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET,
            .dstSet=dset[i],.dstBinding=0,.descriptorCount=1,
            .descriptorType=VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER_DYNAMIC,.pBufferInfo=&bi};
        for(int k=0;k<4;k++)
            wr[1+k]=(VkWriteDescriptorSet){.sType=VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET,
                .dstSet=dset[i],.dstBinding=4u+(uint32_t)k,.descriptorCount=1,
                .descriptorType=VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER,.pImageInfo=&wi};
        for(int k=0;k<16;k++)
            wr[5+k]=(VkWriteDescriptorSet){.sType=VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET,
                .dstSet=dset[i],.dstBinding=8u+(uint32_t)k,.descriptorCount=1,
                .descriptorType=VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER,
                .pImageInfo=(k==0)?&zi[i]:&wi};
        vkUpdateDescriptorSets(g_dev,21,wr,0,NULL);
    }
    rp_begin(dst);
    vkCmdBindPipeline(g_cmd,VK_PIPELINE_BIND_POINT_GRAPHICS,g_dres_pipe[mode]);
    for(uint32_t i=0;i<nband;i++){
        if(!band[i]||dset[i]==VK_NULL_HANDLE) continue;
        uint32_t uoff0[2]={0,0};
        vkCmdBindDescriptorSets(g_cmd,VK_PIPELINE_BIND_POINT_GRAPHICS,g_playout,
                                0,1,&dset[i],2,uoff0);
        VkViewport vpv={.x=0,.y=(float)(i*bh),.width=(float)first->w,
                        .height=(float)bh,.minDepth=0,.maxDepth=1};
        vkCmdSetViewport(g_cmd,0,1,&vpv);
        VkRect2D sc={{0,(int32_t)(i*bh)},{first->w,bh}};
        vkCmdSetScissor(g_cmd,0,1,&sc);
        vkCmdDraw(g_cmd,3,1,0,0);
    }
    rp_end();
    cmd_begin();
    zb.srcAccessMask=VK_ACCESS_SHADER_READ_BIT;
    zb.dstAccessMask=VK_ACCESS_DEPTH_STENCIL_ATTACHMENT_WRITE_BIT;
    zb.oldLayout=VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;
    zb.newLayout=VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL;
    for(uint32_t i=0;i<nband;i++){
        if(!band[i]) continue;
        zb.image=band[i]->z;
        vkCmdPipelineBarrier(g_cmd,stages_for(zb.srcAccessMask,1),
            stages_for(zb.dstAccessMask,0),0,0,0,0,0,1,&zb);
    }
    { static long an; if(++an<=8){
        fprintf(stderr,"[RSXD] shadow atlas resolve zea=0x%x %ux%u bands=%u:",ea,w,h,nband);
        for(uint32_t i=0;i<nband;i++) fprintf(stderr," %s",band[i]?"ok":"--");
        fprintf(stderr,"\n"); } }
    return rt_as_tex(ea,w,h);
}

static Surf* dres_find(uint32_t zea, uint32_t w, uint32_t h){
    Surf* src=0;
    for(int i=0;i<NSURF;i++){
        Surf* c2=&g_surf[i];
        if(!c2->img||!c2->inited||!c2->zea||c2->zea!=zea) continue;
        if(w&&h&&(c2->w!=w||c2->h!=h)){ if(!src) src=c2; continue; }
        src=c2; break;
    }
    if(src) src->last_frame=g_frame;
    return src;
}

static VkImageView depth_as_tex(uint32_t ea, uint32_t w, uint32_t h,
                                uint32_t fmt, uint32_t zfunc){
    Surf* src=dres_find(ea,w,h);
    if(!src) return 0;
    uint32_t nband=1;
    if(w==src->w&&h>src->h&&src->h&&(h%src->h)==0){
        uint32_t zp=src->zpitch?src->zpitch:src->w*4u;
        uint32_t n=h/src->h;
        if(n<=8){
            uint32_t have=1;
            for(uint32_t i=1;i<n;i++)
                if(dres_find(ea+i*zp*src->h,src->w,src->h)) have++;
            if(have>1) nband=n;
        }
    }
    uint32_t bf=fmt&0x9f;
    int mode=(bf>=0x90&&bf<=0x93)?(zfunc?1:2):(src->zfloat?0:1);
    if(nband>1) return dres_atlas(ea,w,h,src,nband,mode);
    int fixed_point=mode;
    { static int last=-1;
      if(fixed_point!=last){ last=fixed_point;
        fprintf(stderr,"[RSXD] depth format = %s (zea=0x%x, live control0=0x%x)\n",
                fixed_point?"FIXED d24":"FLOAT e8m16",ea,g_rsx.control0); } }
    if(!dres_init(fixed_point)) return 0;
    Surf* dst=surf_get(ea,src->w,src->h);
    if(!dst||dst==src) return 0;

    rp_end(); cmd_begin();
    VkImageMemoryBarrier zb={.sType=VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,
        .srcAccessMask=VK_ACCESS_DEPTH_STENCIL_ATTACHMENT_WRITE_BIT,
        .dstAccessMask=VK_ACCESS_SHADER_READ_BIT,
        .oldLayout=VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL,
        .newLayout=VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL,
        .srcQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
        .dstQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
        .image=src->z,.subresourceRange={VK_IMAGE_ASPECT_DEPTH_BIT,0,1,0,1}};
    vkCmdPipelineBarrier(g_cmd,stages_for(zb.srcAccessMask,1),
            stages_for(zb.dstAccessMask,0),0,0,0,0,0,1,&zb);

    VkDescriptorSet dset;
    VkDescriptorSetAllocateInfo dai={.sType=VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO,
        .descriptorPool=g_dpool,.descriptorSetCount=1,.pSetLayouts=&g_dsl};
    if(vkAllocateDescriptorSets(g_dev,&dai,&dset)) return 0;
    VkDescriptorBufferInfo bi={.buffer=g_ubuf,.offset=0,.range=468*16};
    VkDescriptorImageInfo zi={.sampler=g_dres_samp,.imageView=src->zview,
        .imageLayout=VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL};
    VkDescriptorImageInfo wi={.sampler=g_sampler,.imageView=g_white_view,
        .imageLayout=VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL};
    VkWriteDescriptorSet wr[21];
    wr[0]=(VkWriteDescriptorSet){.sType=VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET,
        .dstSet=dset,.dstBinding=0,.descriptorCount=1,
        .descriptorType=VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER_DYNAMIC,.pBufferInfo=&bi};
    for(int i=0;i<4;i++)
        wr[1+i]=(VkWriteDescriptorSet){.sType=VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET,
            .dstSet=dset,.dstBinding=4u+(uint32_t)i,.descriptorCount=1,
            .descriptorType=VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER,.pImageInfo=&wi};
    for(int i=0;i<16;i++)
        wr[5+i]=(VkWriteDescriptorSet){.sType=VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET,
            .dstSet=dset,.dstBinding=8u+(uint32_t)i,.descriptorCount=1,
            .descriptorType=VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER,
            .pImageInfo=(i==0)?&zi:&wi};
    vkUpdateDescriptorSets(g_dev,21,wr,0,NULL);

    rp_begin(dst);
    vkCmdBindPipeline(g_cmd,VK_PIPELINE_BIND_POINT_GRAPHICS,g_dres_pipe[fixed_point]);
    uint32_t uoff0[2]={0,0};
    vkCmdBindDescriptorSets(g_cmd,VK_PIPELINE_BIND_POINT_GRAPHICS,g_playout,
                            0,1,&dset,2,uoff0);
    VkViewport vpv={.x=0,.y=0,.width=(float)dst->w,.height=(float)dst->h,
                    .minDepth=0,.maxDepth=1};
    vkCmdSetViewport(g_cmd,0,1,&vpv);
    VkRect2D sc={{0,0},{dst->w,dst->h}};
    vkCmdSetScissor(g_cmd,0,1,&sc);
    vkCmdDraw(g_cmd,3,1,0,0);
    rp_end();

    cmd_begin();
    zb.srcAccessMask=VK_ACCESS_SHADER_READ_BIT;
    zb.dstAccessMask=VK_ACCESS_DEPTH_STENCIL_ATTACHMENT_WRITE_BIT;
    zb.oldLayout=VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;
    zb.newLayout=VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL;
    vkCmdPipelineBarrier(g_cmd,stages_for(zb.srcAccessMask,1),
            stages_for(zb.dstAccessMask,0),0,0,0,0,0,1,&zb);

    { static long dn; if(++dn<=16)
        fprintf(stderr,"[RSXD] depth resolve zea=0x%x %ux%u\n",ea,dst->w,dst->h); }
    return rt_as_tex(ea,dst->w,dst->h);
}
