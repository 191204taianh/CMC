@echo off

set appname=main

del %appname%.obj
del %appname%.exe

set CurrDrive=%~d0
set CurrPath=%~p0
set FullPath=%CurrDrive%%CurrPath%%appname%

cd /d C:\

masm32\bin\ml /Fo%FullPath%.obj /c /coff %FullPath%.asm

\masm32\bin\polink /SUBSYSTEM:CONSOLE %FullPath%.obj /OUT:%FullPath%.exe

dir %FullPath%.*

echo ==============================================

rem %FullPath%.exe

pause

rem @echo off
rem 
rem set appname=main
rem 
rem del %appname%.obj
rem del %appname%.exe
rem 
rem set CurrDrive=%~d0
rem set CurrPath=%~p0
rem set FullPath=%CurrDrive%%CurrPath%%appname%
rem 
rem cd /d C:\
rem 
rem \masm64\bin64\ml64.exe /Fo%FullPath%.obj /c %FullPath%.asm
rem 
rem \masm64\bin64\link.exe /SUBSYSTEM:CONSOLE /MACHINE:X64 /ENTRY:entry_point /nologo /LARGEADDRESSAWARE %FullPath%.obj /OUT:%FullPath%.exe
rem 
rem dir %FullPath%.*
rem 
rem echo ==============================================
rem 
rem %FullPath%.exe
rem 
rem pause
