package jp.co.axio.masterMentsetSystem.controller;

import java.util.Collections;

import javax.servlet.http.HttpSession;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import jp.co.axio.masterMentsetSystem.common.LogService;

/**
 * 一般利用者メニュー画面処理
 *
 * @author sa
 *
 */
@Controller
public class MenuGeneralController {

	/**
	 * 自処理名
	 */
	private static final String OWN_NAME = "MenuGeneralController";
	/**
	 * 自画面のHTMLテンプレート
	 */
	private static final String OWN_PAGE = "menuGeneral";
	/**
	 * 自処理対象画面名
	 */
	private static final String OWN_TITLE = "メニュー画面";
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
	 * ログインコントローラ
	 */
	@Autowired
	LoginController loginController;

	/**
	 * 初期表示
	 * @param redirectAttributes リダイレクト先に値を引き渡すためのModel
	 * @return ModelAndView
	 */
	@GetMapping("/menuGeneral")
	public ModelAndView index(RedirectAttributes redirectAttributes) {
		LogService.info(OWN_TITLE, OWN_NAME, "初期処理", "開始");
		// ログインチェックここから
		ModelAndView modelAndView = loginController.checkLogin(OWN_TITLE, redirectAttributes);
		if (modelAndView != null) {
			return modelAndView;// ログイン画面へ遷移
		} else {
			modelAndView = new ModelAndView();
		}
		// ログインチェックここまで
		try {
			// ログイン情報以外のsession削除
			Collections.list(session.getAttributeNames()).stream().forEach(e -> {
				if (!"LoginController.loginInfo".equals(e)) {// ログイン情報以外
					session.removeAttribute(e);// 削除
				}
			});
			LogService.info(OWN_TITLE, OWN_NAME, "初期処理", "正常終了");
		} catch (Exception e) {
			LogService.system(OWN_TITLE, OWN_NAME, "初期処理", "失敗した");
			LogService.system(ExceptionUtils.getStackTrace(e));
			String msg = ms.getMessage("ERR001", null, null);
			modelAndView.addObject("errMessage", msg);
			LogService.info(OWN_TITLE, OWN_NAME, "初期処理", "··異常終了");
		}
		modelAndView.setViewName(OWN_PAGE);
		return modelAndView;
	}
}
