//
//  lorgnette-structs.h
//  liblorgnette
//
//  Created by Dmitry Rodionov on 9/26/14.
//  Copyright (c) 2014 rodionovd. All rights reserved.
//

#pragma once

struct dyld_image_info_32 {
	uint32_t imageLoadAddress;
	uint32_t imageFilePath;
	uint32_t imageFileModDate;
};

struct load_command_with_segname {
	uint32_t cmd;
	uint32_t cmdsize;
	uint32_t segname;
};

struct dyld_image_info_64 {
	uint64_t imageLoadAddress;
	uint64_t imageFilePath;
	uint64_t imageFileModDate;
};

struct dyld_all_image_infos_32 {
	uint32_t version;
	uint32_t infoArrayCount;
	uint32_t infoArray;
	uint32_t notification;
	bool processDetachedFromSharedRegion;
	bool libSystemInitialized;
	uint32_t dyldImageLoadAddress;
	uint32_t jitInfo;
	uint32_t dyldVersion;
	uint32_t errorMessage;
	uint32_t terminationFlags;
	uint32_t coreSymbolicationShmPage;
	uint32_t systemOrderFlag;
	uint32_t uuidArrayCount;
	uint32_t uuidArray;
	uint32_t dyldAllImageInfosAddress;
	uint32_t initialImageCount;
	uint32_t errorKind;
	uint32_t errorClientOfDylibPath;
	uint32_t errorTargetDylibPath;
	uint32_t errorSymbol;
	uint32_t sharedCacheSlide;
	uint8_t	 sharedCacheUUID[16];
	uint32_t reserved[16];
};

struct dyld_all_image_infos_64 {
	uint32_t version;
	uint32_t infoArrayCount;
	uint64_t infoArray;
	uint64_t notification;
	int32_t processDetachedFromSharedRegion;
	int32_t libSystemInitialized;
	uint64_t dyldImageLoadAddress;
	uint64_t jitInfo;
	uint64_t dyldVersion;
	uint64_t errorMessage;
	uint64_t terminationFlags;
	uint64_t coreSymbolicationShmPage;
	uint64_t systemOrderFlag;
	uint64_t uuidArrayCount;
	uint64_t uuidArray;
	uint64_t dyldAllImageInfosAddress;
	uint64_t initialImageCount;
	uint64_t errorKind;
	uint64_t errorClientOfDylibPath;
	uint64_t errorTargetDylibPath;
	uint64_t errorSymbol;
	uint64_t sharedCacheSlide;
	uint8_t	 sharedCacheUUID[16];
	uint64_t reserved[16];
};
