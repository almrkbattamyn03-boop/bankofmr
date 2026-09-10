#!/bin/bash
echo "جاري تشغيل السيرفر..."
echo "لازم يكون عندك Node.js متثبت على جهازك (nodejs.org)"
echo ""
cd "$(dirname "$0")"
node server.js
