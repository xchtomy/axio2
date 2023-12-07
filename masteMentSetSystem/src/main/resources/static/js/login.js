// ログイン画面
window.onload = () => {
	// ログインボタンの連続押下防止
      loginInfo.onsubmit = () => {
        btn_submit.disabled = true;
    }
}
