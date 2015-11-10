# libkrbtree
Keyed Red Black Tree

Red Black tree implementation which uses "key" for identification
and comparation, and "data" for container of user defined data.
The reference materials include
http://mindlee.net/2011/08/21/red-black-tree/
and Julienne Walker's red-black tree tutorial at
http://eternallyconfuzzled.com/tuts/datastructures/jsw_tut_rbtree.aspx


This implementation differs from the original tutorial in the following ways:
1. Separate "key" from "data" for identification and comparation
2. Embed the color of nodes into the node pointers to save RAM for a node
3. Other logical adjustments


The original copyright information of
Julienne Walker's red-black tree tutorial is:

Red Black balanced tree library

> Created (Julienne Walker): August 23, 2003
> Modified (Julienne Walker): March 14, 2008

This code is in the public domain. Anyone may
use it or change it in any way that they see
fit. The author assumes no responsibility for
damages incurred through use of the original
code or any variations thereof.

It is requested, but not required, that due
credit is given to the original author and
anyone who has modified the code through
a header comment, such as this one.

