## SSO 发起拼接例子

https://accounts.feishu.cn/accounts/page/login?app_id=1&no_trap=1&redirect_uri=https%3A%2F%2Faccounts.feishu.cn%2Fopen-apis%2Fauthen%2Fv1%2Fauthorize%3Fclient_id%3Dcli_a95de875f6f95bc0%26redirect_uri%3Dhttps%253A%252F%252Fdemo4amflow.vercel.app%252Fchat%252Fcallback%26response_type%3Dcode%26scope%3Dim%253Amessage%253Areadonly%2Bim%253Amessage%2Bim%253Amessage.group_msg%2Bim%253Amessage.group_msg%253Aget_as_user%2Bim%253Amessage.send_as_user%2Bim%253Amessage%253Asend_as_bot%2Boffline_access%26state%3DeyJyZWRpcmVjdFVyaSI6Imh0dHBzOi8vZGVtbzRhbWZsb3cudmVyY2VsLmFwcC9jaGF0L2NhbGxiYWNrIiwiYXQiOjE3NzYzMDU2OTY2NzEsImlhdCI6MTc3NjMwNTY5NiwiZXhwIjoxNzc2MzkyMDk2fQ.6Xq8ewpq9-hWU6NndIJJUTSSDkuVVjiYx9c27HwVnj4

## 注意事项

- 飞书 SSO 跳转只能支持跳转到飞书二级功能（例如聊天、日历），跳转到自定义的页面会报验证失败，这里是一个技巧，发起跳转的时候直接跳转到飞书授权页面，在链接中嵌入了授权页面成功回调地址实现跳转。