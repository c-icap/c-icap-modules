/*
 *  Copyright (C) 2021 Shawn Michael
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct sz_string {
  char *data;
  size_t size;
  size_t buffsz;
};

struct sz_string *double_sz_string(struct sz_string *output) {
    void *voidbuff;

    voidbuff = realloc((void *)output->data, output->buffsz * 2);
    if (voidbuff == NULL) {
        perror("Error during realloc");
        free(output->data);
        free(output);
        return(NULL);
    }
    // Blank the new chunk of RAM
    output->data = (char *)voidbuff;
    output->buffsz *= 2;

    return(output);
}

char *htmlspecialchars(char *input, size_t len) {
    size_t offset = 0;
    char *replacement;  // Double duty as a temp var for constants and
                        // the return value.
    int copysize = 1;
    struct sz_string *output;

    if ((output = (struct sz_string *)malloc(sizeof(struct sz_string))) == NULL) {
        perror("Error during initial malloc");
        return(NULL);
    }
    // Set minimum buffer size to 256 bytes.  This prevents security errors
    // later.  This size *MUST* be larger than the replacement string size
    // for characters.  So if you change this it MUST be at least 6 for
    // "&quot;"
    // Excess here gets freed later with a realloc down to the correct size.
    output->buffsz = 2 * len > 256 ? 2 * len : 256;
    output->size = 0;
    output->data = (char*)malloc(output->buffsz);
    if (output->data == NULL) {
        perror("Error during string malloc");
        free((void*) output);
        return(NULL);
    }

    for (offset = 0; offset < len; offset++) {
        if (output->size > output->buffsz) {
            if ((output = double_sz_string(output)) == NULL) {
                perror("NULL found during double size");
                return(NULL);
            }
        }

        switch (input[offset]) {
            case '&':
                replacement = "&amp;";
                copysize = 5;
                break;
            case '<':
                replacement = "&lt;";
                copysize = 4;
                break;
            case '>':
                replacement = "&gt;";
                copysize = 4;
                break;
            case '\'':
                replacement = "&apos;";
                copysize = 6;
                break;
            case '"':
                replacement = "&quot;";
                copysize = 6;
                break;
            default:
                output->data[output->size++] = input[offset];
                continue;
        }

        // Rest of loop only runs on a replacement being necessary.
        if (output->size + copysize > output->buffsz) {
            if ((output = double_sz_string(output)) == NULL) {
                perror("Error during string malloc");
                return(NULL);
            }
        }
        memcpy((void *)(output->data + output->size), replacement, copysize);
        output->size += copysize;
    }

    if ((replacement = realloc((void *)output->data, output->size + 1)) == NULL) {
        // Unalbe to allocate null character
        free(output->data);
    } else {
        replacement[output->size] = '\0';
    }
    free(output);
    return(replacement);
}


