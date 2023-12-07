package jp.co.axio.masterMentsetSystem.controller;

import java.io.File;
import java.io.FileInputStream;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.tomcat.util.http.fileupload.IOUtils;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import jp.co.axio.masterMentsetSystem.common.LogService;
import jp.co.axio.masterMentsetSystem.service.UserService;

/**
 * ユーザー一覧画面
 *
 * @author axio
 * @version 1.0
 */
@Controller
public class UserListController extends accessController {

    /** 自画面のHTMLテンプレート */
    private static final String OWN_PAGE = "UserSet/userList";

    /** リダイレクトページ */
    private static final String REDIRECT_PAGE = "redirect:./userSet";

    /** 自画面のタイトル */
    public static final String OWN_TITLE = "利用者管理機能：利用者検索";

    @Value("${config.user.file.path}")
    private String userFilePath;

    @Value("${config.userlist.csvname}")
    private String csvName;

	/** ログインコントローラ */
	@Autowired
	LoginController loginController;

	@Autowired
	UserService userListService;

    @Autowired
    MessageSource ms;

	// セッション
	@Autowired
	HttpSession session;

	/**
	 * 初期処理
	 *
	 * @param form フォーム情報
	 * @return ModelAndView
	 */
	@RequestMapping("/userList")
	public ModelAndView init(@ModelAttribute("UserListForm") UserListForm form, RedirectAttributes redirectAttributes) {
		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者一覧初期処理", "開始");

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

		UserListForm redirectForm = (UserListForm) session.getAttribute(form.getClass().getSimpleName());

		if (redirectForm == null) {
			// form初期化
			resetValue(form);
		} else {
			session.removeAttribute(form.getClass().getSimpleName());
            // 詳細画面から戻る場合、遷移前の画面情報を再表示する
			BeanUtils.copyProperties(redirectForm, form);

		}

		modelAndView.addObject(form.getClass().getSimpleName(), form);

		modelAndView.setViewName(OWN_PAGE);
		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者一覧初期処理", "正常終了");

		return modelAndView;
	}

	/**
	 * 検索処理
	 *
	 * @param requestParams - リクエストパラメータ（Map <String, String>）
	 * @return ModelAndView
	 */
	@RequestMapping("/userListSearch")
    public ModelAndView userSearch(@ModelAttribute("userListForm") UserListForm form, RedirectAttributes redirectAttributes) {
		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者一覧検索処理", "開始");

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

		// 検索
		try {
			form.setPageNo("1");
			form.setSortCondition("");
			userListService.selectUserList(form);

		} catch (Exception e) {

			LogService.system(OWN_TITLE, this.getClass().getSimpleName(), "利用者一覧検索処理", "失敗した");
			LogService.system(ExceptionUtils.getStackTrace(e));
			form.setErrMessage(ms.getMessage("ERR001", null, null));
			modelAndView.addObject(form.getClass().getSimpleName(), form);
			modelAndView.setViewName(OWN_PAGE);
			LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者一覧検索処理", "異常終了");
			return modelAndView;
		}


	    modelAndView.addObject(form.getClass().getSimpleName(), form);

		modelAndView.setViewName(OWN_PAGE);
		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者一覧検索処理", "正常終了");

		return modelAndView;
	}

	/**
	 * 次のページ
	 *
	 * @param requestParams - リクエストパラメータ（Map <String, String>）
	 * @return ModelAndView
	 */
	@RequestMapping("/userListShowNextPage")
    public ModelAndView getNextPage(@ModelAttribute("userListForm") UserListForm form, RedirectAttributes redirectAttributes) {
		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者一覧次のページへ移動処理", "開始");

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

		// 検索
		try {
            // 当ページ変更
			int currPage = Integer.valueOf(form.getPageNo()) + 1;
			form.setPageNo(String.valueOf(currPage));
			form.setCountCheck("OK");
			Integer offset = (currPage -1) * 10;
			form.setOffset(offset);

			userListService.selectUserList(form);
		} catch (Exception e) {

			LogService.system(OWN_TITLE, this.getClass().getSimpleName(), "利用者一覧次のページへ移動処理", "失敗した");
			LogService.system(ExceptionUtils.getStackTrace(e));
			form.setErrMessage(ms.getMessage("ERR001", null, null));
			modelAndView.addObject(form.getClass().getSimpleName(), form);
			modelAndView.setViewName(OWN_PAGE);
			LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者一覧次のページへ移動処理", "異常終了");
			return modelAndView;
		}


	    modelAndView.addObject(form.getClass().getSimpleName(), form);

		modelAndView.setViewName(OWN_PAGE);
		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者一覧次のページへ移動処理", "正常終了");

		return modelAndView;
	}

	/**
	 * 前のページ
	 *
	 * @param requestParams - リクエストパラメータ（Map <String, String>）
	 * @return ModelAndView
	 */
	@RequestMapping("/userListShowPrePage")
    public ModelAndView getPrePage(@ModelAttribute("userListForm") UserListForm form, RedirectAttributes redirectAttributes) {
		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者一覧前のページへ移動処理", "開始");

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

		// 検索
		try {
			// 当ページ変更
			int currPage = Integer.valueOf(form.getPageNo()) - 1;
			form.setPageNo(String.valueOf(currPage));
			form.setCountCheck("OK");
			Integer offset = (currPage -1) * 10;
			form.setOffset(offset);

			userListService.selectUserList(form);
		} catch (Exception e) {

			LogService.system(OWN_TITLE, this.getClass().getSimpleName(), "利用者一覧前のページへ移動処理", "失敗した");
			LogService.system(ExceptionUtils.getStackTrace(e));
			form.setErrMessage(ms.getMessage("ERR001", null, null));
			modelAndView.addObject(form.getClass().getSimpleName(), form);
			modelAndView.setViewName(OWN_PAGE);
			LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者一覧前のページへ移動処理", "異常終了");
			return modelAndView;
		}

		modelAndView.addObject(form.getClass().getSimpleName(), form);

		modelAndView.setViewName(OWN_PAGE);
		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者一覧前のページへ移動処理", "正常終了");

		return modelAndView;
	}

	/**
	 * 指定した並び順で検索処理
	 *
	 * @param requestParams - リクエストパラメータ（Map <String, String>）
	 * @return ModelAndView
	 */
	@RequestMapping("/userListChangeOrder")
    public ModelAndView changeOrderBy(@ModelAttribute("userListForm") UserListForm form, RedirectAttributes redirectAttributes) {
		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者一覧並び順変更処理", "開始");

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
		};

		// 検索
		try {
			// 検索結果件数チェック不要
			form.setCountCheck("OK");
			// 1頁目を表示
			form.setPageNo("1");
			// 検索実行
			userListService.selectUserList(form);

		} catch (Exception e) {

			LogService.system(OWN_TITLE, this.getClass().getSimpleName(), "利用者一覧検索処理", "失敗した");
			LogService.system(ExceptionUtils.getStackTrace(e));
			form.setErrMessage(ms.getMessage("ERR001", null, null));
			modelAndView.addObject(form.getClass().getSimpleName(), form);
			modelAndView.setViewName(OWN_PAGE);
			LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者一覧検索処理", "異常終了");
			return modelAndView;
		}

		modelAndView.addObject(form.getClass().getSimpleName(), form);
		modelAndView.setViewName(OWN_PAGE);
		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者一覧並び順変更処理", "正常終了");

		return modelAndView;
	}

	/**
	 * 検索処理
	 *
	 * @param requestParams - リクエストパラメータ（Map <String, String>）
	 * @return ModelAndView
	 * @throws Exception
	 */
	@RequestMapping("/userListDownload")
    public ModelAndView download(@ModelAttribute("userListForm") UserListForm form ,HttpServletResponse response, RedirectAttributes redirectAttributes) throws Exception {
		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者一覧CSVダウンロード処理", "開始");

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

		String realPath = userFilePath;

		// CSV出力情報取得
		File csvFile = userListService.getCsvFile(form , realPath + csvName);

		FileInputStream is = new FileInputStream(csvFile);

		response.setContentType("application/force-download"); //添付でダウンロード
		response.addHeader("Content-Disposition", "attachment;fileName=" + csvFile.getName()); //ファイル名設定

		ServletOutputStream os = response.getOutputStream();

		IOUtils.copy(is, os);
		IOUtils.closeQuietly(is);
		IOUtils.closeQuietly(os);

		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者一覧CSVダウンロード処理", "正常終了");

		return null;
	}

	/**
	 * 指定した並び順で検索処理
	 *
	 * @param requestParams - リクエストパラメータ（Map <String, String>）
	 * @return ModelAndView
	 */
	@RequestMapping("/userSetMove")
    public ModelAndView moveToUserSetPage(@ModelAttribute("userListForm") UserListForm form, RedirectAttributes redirectAttributes) {
		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者詳細画面遷移", "開始");

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

		// 遷移前の検索画面情報保存
		session.setAttribute(form.getClass().getSimpleName(), form);

		ModelMap modelMap = new ModelMap();
		modelMap.addAttribute("userId", form.getCurRowId());
		redirectAttributes.addFlashAttribute("model", modelMap);

		// 詳細画面へ遷移する
		modelAndView.setViewName(REDIRECT_PAGE);
		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者詳細画面遷移", "正常終了");

		return modelAndView;
	}

	/**
	 * フォーム情報初期化
	 *
	 * @param form フォーム情報
	 */
	private void resetValue(UserListForm form) {
		form = new UserListForm();
		// 検索Form初期化
		form.setPrePageFlg("OFF");
		form.setNextPageFlg("OFF");
		form.setZeroCntFlg("OFF");
		form.setCountCheck("");
		form.setPopupShowFlg("OFF");
		form.setPopupMsg("");
	}
}
