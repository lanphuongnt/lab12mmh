# lab12mmh
lab12mmh

```C
{
	"version": "2.0.0",
	"tasks": [
		{
			"type": "shell",
			"label": "C/C++: g++.exe build active file",
			"command": "C:\\msys64\\mingw64\\bin\\g++.exe",
			"args": [
				"-g2",
				"-O3",
				"-DNDEBUG",
				"${file}",
				"-o",
				"${fileDirname}\\${fileBasenameNoExtension}.exe",
				"-D_WIN32_WINNT=0x0501",
				"-pthread",
				"-L${workspaceFolder}\\lib",
				"-l:libcryptopp.a",
				"-I${workspaceFolder}\\include",
				"-Wall",
			],
			"options": {
				"cwd": "C:\\msys64\\mingw64\\bin"
			},
			"problemMatcher": [
				"$gcc"
			],
			"group": {
				"kind": "build",
				"isDefault": true
			},
			"detail": "compiler: C:\\msys64\\mingw64\\bin\\g++.exe"
		}
	]
}
```
