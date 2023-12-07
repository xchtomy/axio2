package jp.co.axio.masterMentsetSystem.controller;

import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.http.HttpSession;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.ietf.ldap.LDAPException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import jp.co.axio.masterMentsetSystem.common.LogService;
import jp.co.axio.masterMentsetSystem.service.LoginService;
import jp.co.axio.masterMentsetSystem.service.LoginService.LoginServiceException;

/**
 * ログインコントローラ
 *
 * @author sa
 */
@Controller
public class LoginController {

	/**
	 * 自処理名
	 */
	private static final String OWN_NAME = "LoginController";
	/**
	 * 自処理対象画面名
	 */
	private static final String OWN_TITLE = "ログイン画面";
	/**
	 * 自処理対象画面Form名
	 */
	private static final String OWN_FORM = "loginInfo";
	/**
	 * 自画面のHTMLテンプレート
	 */
	private static final String OWN_PAGE = "login";
	/**
	 * リダイレクトページ
	 */
	public static final String REDIRECT_PAGE = "redirect:./login";
	/**
	 * リダイレクトページ_改修
	 */
	public static final String LOGOUT_PAGE = "redirect:login";
	/**
	 * メニュー画面のHTMLテンプレート（管理者）
	 */
	private static final String REDIRECT_MENU_PAGE = "redirect:menu";
	/**
	 * メニュー画面のHTMLテンプレート(一般ユーザー)
	 */
	private static final String REDIRECT_MENU_PAGE_G = "redirect:menuGeneral";
	/**
	 * 自処理対象画面Form用のセッションキー
	 */
	private static final String OWN_FORM_SESSION_KEY = "LoginController.loginInfo";

	/**
	 * セッションタイムアウト秒
	 */
	@Value("${config.login.intervalSeconds}")
	private int intervalSeconds;
	/**
	 * メッセージソース
	 */
	@Autowired
	MessageSource ms;
	/**
	 * セッション
	 */
	@Autowired
	HttpSession session;
	/**
	 * ログインサービス
	 */
	@Autowired
	LoginService loginService;

	/**
	 * 初期処理
	 * @param  model        モデル(リダイレクトの場合のパラメータ受け渡し用)
	 * @return modelAndView
	 *
	 */
	@RequestMapping("/login")
	public ModelAndView index(Model model) {
		LogService.info(OWN_TITLE, OWN_NAME, "初期処理", "開始");
		LogService.debug(OWN_TITLE, OWN_NAME, "初期処理", getSessionInfoForDebugLog());
		ModelAndView modelAndView = new ModelAndView();
		try {

			// ログインチェック
			if (isLogin(OWN_TITLE)) {
				if (isAdmin(OWN_TITLE)) {
					// 管理者メニュー
					modelAndView.setViewName(REDIRECT_MENU_PAGE);
				} else {
					// 一般ユーザーメニュー
					modelAndView.setViewName(REDIRECT_MENU_PAGE_G);
				}
			} else {
				if (session != null) {
					session.invalidate();//session破棄
				}
				LoginInfo loginInfo = new LoginInfo();
				LoginInfo form = (LoginInfo) model.getAttribute(OWN_FORM);
				// 遷移前バリデーションエラーを復元
				model.asMap().forEach((final String key, final Object value) -> {
					modelAndView.addObject(key, value);
				});
				// 遷移前パラメータを復元
				if (form != null) {
					loginInfo.setInputId(form.getInputId());
					loginInfo.setPass(form.getPass());
					loginInfo.setErrMessage(form.getErrMessage());
				}
				modelAndView.addObject(OWN_FORM, loginInfo);
				modelAndView.setViewName(OWN_PAGE);
				LogService.debug(OWN_TITLE, OWN_NAME, "初期処理", getSessionInfoForDebugLog());
			}
			LogService.info(OWN_TITLE, OWN_NAME, "初期処理", "正常終了");
			LogService.debug(OWN_TITLE, OWN_NAME, "初期処理", "正常終了" + modelAndView.getViewName());
		} catch (Exception e) {
			LogService.debug(OWN_TITLE, OWN_NAME, "ログアウト処理", getSessionInfoForDebugLog());
			// エラーログ出力
			printExceptionLog(e, "ログアウト処理");
			// エラーメッセージをセット
			LoginInfo form = new LoginInfo();
			form.setErrMessage(ms.getMessage("ERR001", null, null));
			modelAndView.addObject(OWN_FORM, form);
		}
		return modelAndView;
	}

	/**
	 * ログイン(認証)
	 * @param  form               入力パラメータ
	 * @param  result             バリデーション結果
	 * @param  redirectAttributes リダイレクト先に値を引き渡すためのModel
	 * @return modelAndView
	 */
	@RequestMapping("/loginAuthentication")
	public ModelAndView authentication(@ModelAttribute(OWN_FORM) @Validated LoginInfo form, BindingResult result,
			RedirectAttributes redirectAttributes) {
		LogService.info(OWN_TITLE, OWN_NAME, "ログイン処理", "開始");
		ModelAndView modelAndView = new ModelAndView();

		// バリデーションエラーの場合
		if (result.hasErrors()) {
			// バリデーションエラーをリダイレクト用にセット
			result.getModel().forEach((String key, Object value) -> {
				redirectAttributes.addFlashAttribute(key, value);
			});
			redirectAttributes.addFlashAttribute(OWN_FORM, form);
			modelAndView.setViewName(REDIRECT_PAGE);
			return modelAndView;
		}

		try {
			// ログイン処理
			LoginInfo loginInfo = loginService.authentication(form);
			LogService.debug(OWN_TITLE, OWN_NAME, "ログイン処理", getSessionInfoForDebugLog());
			// LDAP認証は出来たがDBからデータが取れない場合、エラーメッセージをセットして返却
			if (loginInfo == null) {
				form.setErrMessage(ms.getMessage("MSTO0009M0001", null, null));// パスワードが正しくありません。入力し直してください。
				redirectAttributes.addFlashAttribute(OWN_FORM, form);
				modelAndView.setViewName(REDIRECT_PAGE);
				return modelAndView;
			}
			// ログイン情報が取得出来た場合、ログイン情報をsessionにセット
			session.setAttribute(OWN_FORM_SESSION_KEY, loginInfo);
			session.setMaxInactiveInterval(intervalSeconds);

			// 正常終了:メニュー画面へ遷移
			if (isAdmin(OWN_TITLE)) {
				// 管理者メニュー
				modelAndView.setViewName(REDIRECT_MENU_PAGE);
			} else {
				// 一般ユーザーメニュー
				modelAndView.setViewName(REDIRECT_MENU_PAGE_G);
			}
			LogService.info(OWN_TITLE, OWN_NAME, "ログイン処理", "正常終了");
			return modelAndView;
		} catch (Exception e) { // 異常終了:自画面へ遷移
			// エラーログ出力
			printExceptionLog(e, "ログイン処理");
			// エラーメッセージをセット
			String msg = ms.getMessage("ERR001", null, null);
			if (e instanceof LDAPException) {
				// 認証系の例外の場合
				if (LDAPException.INVALID_CREDENTIALS == ((LDAPException) e).getResultCode()) {
					// 不正な bind ユーザ、もしくは bind パスワードを指定した際にエラーコード49が返る
					msg = ms.getMessage("MSTO0009M0001", null, null);// パスワードが正しくありません。入力し直してください。
				} else {
					msg = ms.getMessage("MSTO0009M0002", null, null);// ログインに失敗しました。
				}
			} else if (e instanceof LoginServiceException) {
				// ログインサービス例外の場合
				msg = e.getMessage();
			}
			form.setErrMessage(msg);
			redirectAttributes.addFlashAttribute(OWN_FORM, form);
			modelAndView.setViewName(REDIRECT_PAGE);
			return modelAndView;
		}
	}

	/**
	 * ログアウト
	 * @param  redirectAttributes リダイレクト先に値を引き渡すためのModel
	 * @return ModelAndView       ログイン画面
	 */
	@RequestMapping("/logout")
	public ModelAndView logout(RedirectAttributes redirectAttributes) {
		LogService.info(OWN_TITLE, OWN_NAME, "ログアウト処理", "開始");
		LoginInfo form = new LoginInfo();
		ModelAndView modelAndView = new ModelAndView();
		try {
			LogService.debug(OWN_TITLE, OWN_NAME, "ログアウト処理", getSessionInfoForDebugLog());
			// セッションを破棄
			session.invalidate();
			// メッセージをセット
			form.setErrMessage(ms.getMessage("CMN0010", null, null));
			LogService.info(OWN_TITLE, OWN_NAME, "ログアウト処理", "正常終了");
			LogService.debug(OWN_TITLE, OWN_NAME, "ログアウト処理", getSessionInfoForDebugLog());

		} catch (Exception e) {
			LogService.debug(OWN_TITLE, OWN_NAME, "ログアウト処理", getSessionInfoForDebugLog());
			// エラーログ出力
			printExceptionLog(e, "ログアウト処理");
			// エラーメッセージをセット
			form.setErrMessage(ms.getMessage("ERR001", null, null));
		}
		redirectAttributes.addFlashAttribute(OWN_FORM, form);
		modelAndView.setViewName(REDIRECT_PAGE);
		return modelAndView;

	}

	/**
	 * ログインチェック
	 * @param  title              呼び出し元画面名
	 * @param  redirectAttributes リダイレクト先に値を引き渡すためのModel
	 * @return ModelAndView       ログインしていない場合、ログイン画面を返却。
	 */
	public ModelAndView checkLogin(String title, RedirectAttributes redirectAttributes) {
		ModelAndView modelAndView = new ModelAndView();
		LoginInfo form = new LoginInfo();
		try {
			if (!isLogin(title)) {
				// メッセージをセット
				String msg = ms.getMessage("CMN0009", null, null);
				form.setErrMessage(msg);
				redirectAttributes.addFlashAttribute(OWN_FORM, form);
				modelAndView.setViewName(REDIRECT_PAGE);
				LogService.debug(title, OWN_NAME, "ログインチェック処理", "ログイン画面へ遷移");
				return modelAndView;
			}
		} catch (Exception e) {
			LogService.debug(OWN_TITLE, OWN_NAME, "ログインチェック処理", getSessionInfoForDebugLog());
			// エラーログ出力
			printExceptionLog(e, "ログインチェック処理");
			// エラーメッセージをセット
			form.setErrMessage(ms.getMessage("ERR001", null, null));
			redirectAttributes.addFlashAttribute(OWN_FORM, form);
			modelAndView.setViewName(REDIRECT_PAGE);
			return modelAndView;
		}
		return null;
	}

	/**
	 * ログインチェック
	 * @param  title   呼び出し元画面名
	 * @return Boolean true:ログイン中, false:ログイン中でない
	 */
	@ResponseBody
	@RequestMapping("/isLogin")
	public Boolean isLogin(String title) {
		LogService.info(title, OWN_NAME, "ログインチェック(boolean)処理", "開始");
		Boolean isLogin = false;
		LogService.debug(title, OWN_NAME, "ログインチェック(boolean)処理", getSessionInfoForDebugLog());
		// セッションの存在チェック
		if (session != null) {
			if (session.getAttribute(OWN_FORM_SESSION_KEY) != null &&
					!StringUtils.isEmpty(((LoginInfo) session.getAttribute(OWN_FORM_SESSION_KEY)).getUserId())) {
				isLogin = true;
			}
		}
		LogService.debug(title, OWN_NAME, "ログインチェック(boolean)処理", "正常終了 : 判定結果 = " + isLogin);
		LogService.info(title, OWN_NAME, "ログインチェック(boolean)処理", "正常終了");
		return isLogin;
	}


	/**
	 * 権限チェック
	 * @param  title              呼び出し元画面名
	 * @param  redirectAttributes リダイレクト先に値を引き渡すためのModel
	 * @return ModelAndView       管理者権限では場合、ログイン画面を返却。
	 */
	public ModelAndView checkAdmin(String title, RedirectAttributes redirectAttributes) {
		ModelAndView modelAndView = new ModelAndView();
		LoginInfo form = new LoginInfo();
		try {
			if (!isAdmin(title)) {
				// メッセージをセット
				String msg = ms.getMessage("CMN0011", null, null);
				form.setErrMessage(msg);
				redirectAttributes.addFlashAttribute(OWN_FORM, form);
				modelAndView.setViewName(REDIRECT_PAGE);
				LogService.debug(title, OWN_NAME, "権限チェック処理", "ログイン画面へ遷移");
				return modelAndView;
			}
		} catch (Exception e) {
			LogService.debug(OWN_TITLE, OWN_NAME, "権限チェック処理", getSessionInfoForDebugLog());
			// エラーログ出力
			printExceptionLog(e, "権限チェック処理");
			// エラーメッセージをセット
			form.setErrMessage(ms.getMessage("ERR001", null, null));
			redirectAttributes.addFlashAttribute(OWN_FORM, form);
			modelAndView.setViewName(REDIRECT_PAGE);
			return modelAndView;
		}
		return null;
	}

	/**
	 * 権限チェック
	 * @param title    呼び出し元画面名
	 * @return Boolean true:管理者, false:管理者でない
	 */
	public Boolean isAdmin(String title) {
		LogService.info(title, OWN_NAME, "権限チェック(boolean)処理", "開始");
		Boolean isAdmin = false;
		if (session != null) {
			if (session.getAttribute(OWN_FORM_SESSION_KEY) != null) {
				// セッション.ログイン情報から管理者権限フラグ取得
				isAdmin = ((LoginInfo) session.getAttribute(OWN_FORM_SESSION_KEY)).getIsAdmin();
			}
		}
		LogService.debug(title, OWN_NAME, "権限チェック(boolean)処理", "正常終了 : 判定結果 = " + isAdmin);
		LogService.info(title, OWN_NAME, "権限チェック(boolean)処理", "正常終了");
		return isAdmin;
	}

	/**
	 * セッションの中身を文字列で返却
	 * @return String セッションの中身文字列
	 */
	private String getSessionInfoForDebugLog() {
		if (session == null) {
			return "";
		}
		// セッションの中身をMapに変換
		Map<String, Object> attributeMap = Collections.list(session.getAttributeNames()).stream()
				.collect(Collectors.toUnmodifiableMap(key -> key, key -> session.getAttribute(key)));

		return "session: isNew=" + session.isNew() + ", id=" + session.getId() + ", attribute="
				+ String.valueOf(attributeMap);
	}

	/**
	 * 異常終了時のログ出力(system,info)
	 * @param e           例外
	 * @param processName 処理名
	 */
	private void printExceptionLog(Exception e, String processName) {
		LogService.system(OWN_TITLE, OWN_NAME, processName, "異常終了");
		LogService.system(ExceptionUtils.getStackTrace(e));
		LogService.info(OWN_TITLE, OWN_NAME, processName, "異常終了" + e.getMessage());
	}
}
