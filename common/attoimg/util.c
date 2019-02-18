/*
 * Copyright 2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <stdio.h>
#include <stdlib.h>
#include "util.h"

char *read_image(const char *filename, unsigned long *size)
{
    FILE *fd = NULL;
    char *image = NULL, *tmp;
    unsigned int bytes;

    if ( (filename == NULL) || (size == NULL) )
        return NULL;

    if ( !(fd = fopen(filename, "rb")) )
    {
        PERROR("Could not open image");
        goto out;
    }

    *size = 0;

#define CHUNK 1*1024*1024
    while(1)
    {
        if ( (tmp = realloc(image, *size + CHUNK)) == NULL )
        {
            PERROR("Could not allocate memory for kernel image");
            free(image);
            image = NULL;
            goto out;
        }
        image = tmp;

        bytes = fread(image + *size, 1, CHUNK, fd);
        if (ferror(fd)) {
            PERROR("Error reading kernel image");
            free(image);
            image = NULL;
            goto out;
        }
        *size += bytes;
        if (feof(fd))
            goto out;
    }
#undef CHUNK

 out:
    if ( *size == 0 )
    {
        PERROR("Could not read kernel image");
        free(image);
        image = NULL;
    }
    else if ( image )
    {
        /* Shrink allocation to fit image. */
        tmp = realloc(image, *size);
        if ( tmp )
            image = tmp;
    }

    if ( fd )
        fclose(fd);
    return image;
}
