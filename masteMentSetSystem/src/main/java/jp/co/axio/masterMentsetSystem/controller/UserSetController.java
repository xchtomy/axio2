package jp.co.axio.masterMentsetSystem.controller;


import java.io.File;
import java.io.FileInputStream;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.tomcat.util.http.fileupload.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import jp.co.axio.masterMentsetSystem.common.LogService;
import jp.co.axio.masterMentsetSystem.dto.UserDetailDto;
import jp.co.axio.masterMentsetSystem.service.UserSetService;

/**
 * 利用者詳細画面
 *
 * @author axio
 * @version 1.0
 */
@Controller
public class UserSetController extends accessController {

    /** 自画面のHTMLテンプレート */
    private static final String OWN_PAGE = "UserSet/userSet";

    /** リダイレクトページ */
    private static final String REDIRECT_PAGE = "redirect:./userSet";

    /** 自画面のタイトル */
    public static final String OWN_TITLE = "利用者管理機能：利用者検索";

	/** 検索画面URL */
	private static final String SEARCH_PAGE = "redirect:./userList";

	/** ログインコントローラ */
	@Autowired
	LoginController loginController;

    @Value("${config.user.file.path}")
    private String userFilePath;

    @Value("${config.userset.csvname}")
    private String csvName;

	@Autowired
	UserSetService userSetService;

    @Autowired
    MessageSource ms;

	@Autowired
	HttpSession session;

	// ログイン情報
	private static final String LOGIN_FORM_SESSION_KEY = "LoginController.loginInfo";

	/**
	 * 初期処理
	 *
	 * @param requestParams - リクエストパラメータ（Map <String, String>）
	 * @return ModelAndView
	 */
	@RequestMapping("/userSet")
    public ModelAndView init(@ModelAttribute("model")ModelMap modelMap,  Model model, RedirectAttributes redirectAttributes)  {
		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者情報登録初期処理", "開始");

		ModelAndView modelAndView = loginController.checkLogin(OWN_TITLE, redirectAttributes);

		if (modelAndView != null) {
			return modelAndView;// ログイン画面へ遷移
		} else {
			// 2022/06/22　権限チェック追加
			modelAndView = loginController.checkAdmin(OWN_TITLE, redirectAttributes);
			if (modelAndView != null) {
				return modelAndView;// ログイン画面へ遷移
			} else {
				modelAndView = new ModelAndView();
			}
		}

		/**
		 * 2022/08/05追記
		 * 再読み込み時エラーになるため、
		 * 検索画面に戻す
		 */
		if (modelMap.size() == 0) {
			modelAndView.setViewName(SEARCH_PAGE);
			return modelAndView;
		}


		UserSetForm form = new UserSetForm();

		String userId = (String) modelMap.get("userId");
		String saveFlg = (String) modelMap.get("saveFlg");
		String msg = (String) modelMap.get("message");

		if ("ON".equals(saveFlg)) {
			model.addAttribute("axioMessage", msg);
		}

		//アクセストークン設定 二重送信防止
		saveAccessToken(form);

		// 検索
	    try {
	    	UserDetailDto dto = userSetService.getUserDetail(form, userId);

	    	form.setUserDetailDto(dto);
		} catch (Exception e) {
			LogService.system(OWN_TITLE, this.getClass().getSimpleName(), "利用者情報登録初期処理", "失敗した");
			LogService.system(ExceptionUtils.getStackTrace(e));
			form.setErrMessage(ms.getMessage("ERR001", null, null));
			form.setErrFlg("ON");
			modelAndView.addObject(form.getClass().getSimpleName(), form);
			modelAndView.setViewName(OWN_PAGE);
			LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者情報登録初期処理", "異常終了");
			return modelAndView;
		}

	    modelAndView.addObject(form.getClass().getSimpleName(), form);

		modelAndView.setViewName(OWN_PAGE);
		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者情報登録初期処理", "正常終了");


		return modelAndView;
	}

	/**
	 * ユーザ情報保存処理
	 *
	 * @param requestParams - リクエストパラメータ（Map <String, String>）
	 * @return ModelAndView
	 * @throws Exception
	 */
	@RequestMapping("/userSetSave")
    public ModelAndView save(UserSetForm form, RedirectAttributes redirectAttributes) {
		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者情報保存処理", "開始");

		ModelAndView modelAndView = loginController.checkLogin(OWN_TITLE, redirectAttributes);

		if (modelAndView != null) {
			return modelAndView;// ログイン画面へ遷移
		} else {
			// 2022/06/22　権限チェック追加
			modelAndView = loginController.checkAdmin(OWN_TITLE, redirectAttributes);
			if (modelAndView != null) {
				return modelAndView;// ログイン画面へ遷移
			} else {
				modelAndView = new ModelAndView();
			}
		}

		ModelMap modelMap = new ModelMap();

		try {
	        LoginInfo loginInfo = (LoginInfo) session.getAttribute(LOGIN_FORM_SESSION_KEY);

			userSetService.updateUserDetail(form, loginInfo.getUserId());

		} catch (Exception e) {
			LogService.system(OWN_TITLE, this.getClass().getSimpleName(), "利用者情報保存処理", "失敗した");
			LogService.system(ExceptionUtils.getStackTrace(e));

			modelMap.addAttribute("userId", form.getUserDetailDto().getUserId());

			if (ExceptionUtils.getStackTrace(e).indexOf("一意性制約") > 0) {
				// 本務と同じ所属の兼務追加時、できないメッセージを返す
				modelMap.addAttribute("message", ms.getMessage("MSTO0013M0007", null, null));
			} else {
				// その以外、システムエラー
				modelMap.addAttribute("message", ms.getMessage("ERR001", null, null));
			}

			modelMap.addAttribute("saveFlg", "ON");
			redirectAttributes.addFlashAttribute("model", modelMap);

			modelAndView.setViewName(REDIRECT_PAGE);
			LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者情報保存処理", "異常終了");
			return modelAndView;
		}

        // 詳細画面再表示
		modelAndView.setViewName(REDIRECT_PAGE);

		modelMap.addAttribute("userId", form.getUserDetailDto().getUserId());
		// 完了メッセージ
		String msg = ms.getMessage("CMN0003", new String[] { "利用者情報登録" }, null);
		modelMap.addAttribute("saveFlg", "ON");
		modelMap.addAttribute("message", msg);

		redirectAttributes.addFlashAttribute("model", modelMap);

		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者情報保存処理", "正常終了");

		return modelAndView;
	}

	/**
	 * 利用者CSV
	 *
	 * @param form
	 * @param response
	 * @return
	 * @throws Exception
	 */
	@RequestMapping("/userSetCsvDownload")
	public ModelAndView csvDownload(@ModelAttribute("userSetForm") UserSetForm form, HttpServletResponse response,
			RedirectAttributes redirectAttributes) throws Exception {
		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者情報CSVダイアログ", "開始");

		ModelAndView modelAndView = loginController.checkLogin(OWN_TITLE, redirectAttributes);

		if (modelAndView != null) {
			return modelAndView;// ログイン画面へ遷移
		} else {
			// 2022/06/22　権限チェック追加
			modelAndView = loginController.checkAdmin(OWN_TITLE, redirectAttributes);
			if (modelAndView != null) {
				return modelAndView;// ログイン画面へ遷移
			} else {
				modelAndView = new ModelAndView();
			}
		}

        // CSV作成
		String userId = form.getUserDetailDto().getUserId();
		UserSetForm csvForm = new UserSetForm();

    	userSetService.getUserDetail(csvForm, userId);

		String realPath = userFilePath;
		String csvName = this.csvName + form.getUserDetailDto().getUserId() + ".csv";

		// CSV出力情報取得
		File csvFile = userSetService.getCsvFile(csvForm , realPath + csvName);

		FileInputStream is = new FileInputStream(csvFile);

		response.setContentType("application/force-download");//添付でダウンロード
		response.addHeader("Content-Disposition", "attachment;fileName=" + csvFile.getName());//ファイル名設定

		ServletOutputStream os = response.getOutputStream();


		IOUtils.copy(is, os);
		IOUtils.closeQuietly(is);
		IOUtils.closeQuietly(os);

		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者情報CSVダイアログ", "正常終了");

		return null;
	}

}
