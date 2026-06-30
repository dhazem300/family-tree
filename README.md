# Railway Docker sqlite3 fix

ضع الملفين `Dockerfile` و `.dockerignore` في جذر المشروع بجانب `package.json`.

ثم نفّذ:

```bash
git add Dockerfile .dockerignore package.json package-lock.json .gitignore
git commit -m "Use Dockerfile for Railway sqlite3"
git push
git status
```

في Railway تأكد من Build Logs أن السطر التالي ظهر:

```text
Using detected Dockerfile
```

ثم تأكد أن البناء وصل إلى أمر:

```text
test -f node_modules/sqlite3/build/Release/node_sqlite3.node
```

إذا فشل قبل هذا السطر، ابعت Build Logs. إذا نجح ووصل للـ Deploy ثم Crash، ابعت Deploy Logs بعد `npm start`.
