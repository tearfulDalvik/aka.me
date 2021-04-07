---
layout: post
title: Word Line Spacer
category: work
permalink: work/word-line-spacer/
tags: works_tools
last-modified: 201708131400
scheme-text: "#1b24fb"
scheme-link: "#1b24fb"
---

> 仅适用于 Microsoft Word，且必须支持 VBA 脚本

前两天语文老师想让我来给我们班做一份练字用的小册子，要求是需要方格子，并且是上面一行下面要空一行留给大家写字用。可是在用 Word 创建完格子后才发现格子是底图，并不是和文字挂钩的，这时如果调整行距会导致整篇都混乱掉，只好老老实实的保持行高，在每一行结束都换行一次了。

由于数据量非常大，至少有 50 页，只好用 “宏” 来解决  

```vb
Sub 宏1()
    '选中整行，以便确定此行是否有内容
    Selection.Expand wdLine
    'MsgBox (Len(Selection.Text) = 1)
    If Len(Selection.Text) = 1 Then
        '此时没有内容，但是不知道为什么会返回有一个字，这里的 1 请根据测试更改

        '向下移动一行
        Selection.MoveDown Unit:=wdLine, Count:=1
    End If
    '将光标移动到此行的最后一个字
    Selection.EndKey Unit:=wdLine
    '键入两次换行
    Selection.TypeParagraph
    Selection.TypeParagraph
End Sub
```
**因为我使用了快捷键绑定以便在程序运行出现偏差时实时做出修正，所以在程序中没有使用循环。**

当此脚本跑遍了整个文档时，基本就大功告成了，但是你会发现这时会多出很多行，其实解决起来也很简单，只需要在 “查找和替换” 中把 ```^p^p^p``` 替换为 ```^p^p``` 即可，这一步需要重复多次，直到没有内容被替换为止。