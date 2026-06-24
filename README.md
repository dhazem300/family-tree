# family-tree

## تحديث الخصوصية وتسجيل المستخدمين

تم تحويل الموقع إلى موقع خاص Private Site:

- أي صفحة عامة أو API أو صورة داخل الموقع تحتاج تسجيل دخول مستخدم عادي.
- لوحة الإدارة لها تسجيل دخول منفصل كما هي على `/admin/login`.
- صفحات المستخدمين الجديدة:
  - `/login` تسجيل دخول المستخدمين.
  - `/register` إنشاء حساب جديد.
  - `/logout` تسجيل خروج المستخدمين.
- صفحة الإدارة الجديدة:
  - `/admin/users` عرض مستخدمي الموقع وإحصائياتهم وآخر نشاطهم.
  - `/admin/users/:id` تفاصيل مستخدم وسجل نشاطه.

### Google / Apple OAuth

تم تجهيز المسارات والأزرار الخاصة بالدخول عبر Google و Apple، لكنها تحتاج مفاتيح OAuth في ملف `.env` وتثبيت الحزم الجديدة:

```bash
npm install
npm start
```

أضف القيم التالية عند التفعيل:

```env
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_CALLBACK_URL=/auth/google/callback

APPLE_CLIENT_ID=
APPLE_TEAM_ID=
APPLE_KEY_ID=
APPLE_PRIVATE_KEY_PATH=
APPLE_PRIVATE_KEY=
APPLE_CALLBACK_URL=/auth/apple/callback
```

روابط Callback أثناء التجربة المحلية:

```text
http://localhost:3000/auth/google/callback
http://localhost:3000/auth/apple/callback
```


## تحديث الحسابات الخاصة وأعضاء العائلة

تمت إضافة نظام حساب شخصي كامل للموقع الخاص:

- `/login` تسجيل الدخول.
- `/register` إنشاء حساب مع البيانات الشخصية.
- `/account` صفحة حسابي وتعديل الصورة وبيانات التواصل والحسابات الاجتماعية.
- `/family-members` صفحة أعضاء العائلة المسجلين.
- `/family-members/:id` صفحة بيانات كل عضو مع أزرار التواصل.
- `/admin/users` إدارة مستخدمي الموقع ونشاطهم من لوحة الإدارة.

البيانات الإجبارية عند إنشاء حساب عادي: الاسم، اسم الأب، البريد الإلكتروني، رقم الجوال، وكلمة المرور. باقي البيانات اختيارية.

### Google / Apple OAuth

الأزرار ظاهرة ومفعلة كمسارات. لكي تعمل فعليًا اربط مفاتيح OAuth في `.env`:

```env
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_CALLBACK_URL=/auth/google/callback

APPLE_CLIENT_ID=
APPLE_TEAM_ID=
APPLE_KEY_ID=
APPLE_PRIVATE_KEY_PATH=
APPLE_PRIVATE_KEY=
APPLE_CALLBACK_URL=/auth/apple/callback
```

بعد دخول المستخدم عبر Google أو Apple، إذا كانت البيانات الأساسية ناقصة سيتم تحويله تلقائيًا إلى `/account?complete=1` لاستكمال البيانات.


## تحديث الشات والحسابات

تمت إضافة نظام رسائل داخل الموقع:

- `/chat` مركز الرسائل.
- `/chat/public` الشات العام لكل أعضاء العائلة.
- `/chat/private/:userId` محادثة خاصة بين عضو وعضو.
- دعم إرسال نصوص + صور + تسجيلات صوتية + إيموجي.
- `/admin/chats` إدارة المحادثات: إغلاق/فتح الشات العام، حذف الرسائل، وإيقاف المحادثات الخاصة.

### Apple Sign in

تسجيل Apple على الويب يحتاج دومين حقيقي HTTPS، ولا يعمل على `localhost` كرابط رجوع. ضع في Apple Developer نفس الرابط الموجود في `.env` مثل:

```env
APPLE_CALLBACK_URL=https://your-domain.com/auth/apple/callback
```

واستخدم `Services ID` في `APPLE_CLIENT_ID`، وليس Bundle ID الخاص بتطبيق iOS.
