# simple-flannel
simple-flannel has core flannel func, remove some useless code, only remain core func.

simple-flannel 包含了flannel的核心功能，去掉了无用的一些代码，只保留了vxlan的backend，方便用于研读flannel源码

## build二进制文件
`make flanneld`

这个simple flannel大小为9M，比flannel原来的34M要小, 并且可以直接使用


