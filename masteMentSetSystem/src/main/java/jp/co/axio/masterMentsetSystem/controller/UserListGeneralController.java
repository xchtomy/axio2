package jp.co.axio.masterMentsetSystem.controller;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpSession;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import jp.co.axio.masterMentsetSystem.common.LogService;
import jp.co.axio.masterMentsetSystem.dto.UserMaxCntDto;
import jp.co.axio.masterMentsetSystem.service.UserGeneralService;

/**
 * ユーザー一覧画面
 *
 * @author axio
 * @version 1.0
 */
@Controller
public class UserListGeneralController extends accessController {

    /** 自画面のHTMLテンプレート */
    private static final String OWN_PAGE = "UserSet/userListGeneral";

    /** 自画面のタイトル */
    public static final String OWN_TITLE = "利用者管理機能：利用者検索";

    @Value("${config.userlist.maxCntList}")
    private String maxCntList;
    @Value("${config.userlist.defaultCnt}")
    private String defaultCnt;

	/** ログインコントローラ */
	@Autowired
	LoginController loginController;

	@Autowired
	UserGeneralService userListGeneralService;

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
	@RequestMapping("/userListGeneral")
	public ModelAndView init(@ModelAttribute("UserListForm") UserListForm form, RedirectAttributes redirectAttributes) {
		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者一覧初期処理", "開始");

		ModelAndView modelAndView = loginController.checkLogin(OWN_TITLE, redirectAttributes);

		if (modelAndView != null) {
			return modelAndView;// ログイン画面へ遷移
		} else {
			modelAndView = new ModelAndView();
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

		// 最大件数リスト取得
		form.setUserMaxCntList(getMaxCntList());
		// Default件数
		form.setCntSelected(defaultCnt);

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
	@RequestMapping("/userListGeneralSearch")
    public ModelAndView userSearch(@ModelAttribute("userListForm") UserListForm form, RedirectAttributes redirectAttributes) {
		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者一覧検索処理", "開始");

		ModelAndView modelAndView = loginController.checkLogin(OWN_TITLE, redirectAttributes);

		if (modelAndView != null) {
			return modelAndView;// ログイン画面へ遷移
		} else {
			modelAndView = new ModelAndView();
		}

		// 検索
		try {
			form.setPageNo("1");
			form.setSortCondition("");
			form.setInvUserFlg("OFF");	// 退職者は含まない
			userListGeneralService.selectUserList(form);

		} catch (Exception e) {

			LogService.system(OWN_TITLE, this.getClass().getSimpleName(), "利用者一覧検索処理", "失敗した");
			LogService.system(ExceptionUtils.getStackTrace(e));
			form.setErrMessage(ms.getMessage("ERR001", null, null));
			modelAndView.addObject(form.getClass().getSimpleName(), form);
			modelAndView.setViewName(OWN_PAGE);
			LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者一覧検索処理", "異常終了");
			return modelAndView;
		}

		// 最大件数リスト取得
		form.setUserMaxCntList(getMaxCntList());

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
	@RequestMapping("/userListGeneralShowNextPage")
    public ModelAndView getNextPage(@ModelAttribute("userListForm") UserListForm form, RedirectAttributes redirectAttributes) {
		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者一覧次のページへ移動処理", "開始");

		ModelAndView modelAndView = loginController.checkLogin(OWN_TITLE, redirectAttributes);

		if (modelAndView != null) {
			return modelAndView;// ログイン画面へ遷移
		} else {
			modelAndView = new ModelAndView();
		}

		// 検索
		try {
            // 当ページ変更
			int currPage = Integer.valueOf(form.getPageNo()) + 1;
			form.setPageNo(String.valueOf(currPage));
			form.setCountCheck("OK");
//			Integer offset = (currPage -1) * 10;
			// 選択したページ件数
			int maxCnt = Integer.parseInt(form.getCntSelected());
			Integer offset = (currPage -1) * maxCnt;

			form.setOffset(offset);
			form.setInvUserFlg("OFF");	// 退職者は含まない

			userListGeneralService.selectUserList(form);
		} catch (Exception e) {

			LogService.system(OWN_TITLE, this.getClass().getSimpleName(), "利用者一覧次のページへ移動処理", "失敗した");
			LogService.system(ExceptionUtils.getStackTrace(e));
			form.setErrMessage(ms.getMessage("ERR001", null, null));
			modelAndView.addObject(form.getClass().getSimpleName(), form);
			modelAndView.setViewName(OWN_PAGE);
			LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者一覧次のページへ移動処理", "異常終了");
			return modelAndView;
		}

		// 最大件数リスト取得
		form.setUserMaxCntList(getMaxCntList());

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
	@RequestMapping("/userListGeneralShowPrePage")
    public ModelAndView getPrePage(@ModelAttribute("userListForm") UserListForm form, RedirectAttributes redirectAttributes) {
		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者一覧前のページへ移動処理", "開始");

		ModelAndView modelAndView = loginController.checkLogin(OWN_TITLE, redirectAttributes);

		if (modelAndView != null) {
			return modelAndView;// ログイン画面へ遷移
		} else {
			modelAndView = new ModelAndView();
		}

		// 検索
		try {
			// 当ページ変更
			int currPage = Integer.valueOf(form.getPageNo()) - 1;
			form.setPageNo(String.valueOf(currPage));
			form.setCountCheck("OK");
//			Integer offset = (currPage -1) * 10;
			// 選択したページ件数
			int maxCnt = Integer.parseInt(form.getCntSelected());
			Integer offset = (currPage -1) * maxCnt;

			form.setOffset(offset);
			form.setInvUserFlg("OFF");	// 退職者は含まない

			userListGeneralService.selectUserList(form);
		} catch (Exception e) {

			LogService.system(OWN_TITLE, this.getClass().getSimpleName(), "利用者一覧前のページへ移動処理", "失敗した");
			LogService.system(ExceptionUtils.getStackTrace(e));
			form.setErrMessage(ms.getMessage("ERR001", null, null));
			modelAndView.addObject(form.getClass().getSimpleName(), form);
			modelAndView.setViewName(OWN_PAGE);
			LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者一覧前のページへ移動処理", "異常終了");
			return modelAndView;
		}

		// 最大件数リスト取得
		form.setUserMaxCntList(getMaxCntList());

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
	@RequestMapping("/userListGeneralChangeOrder")
    public ModelAndView changeOrderBy(@ModelAttribute("userListForm") UserListForm form, RedirectAttributes redirectAttributes) {
		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者一覧並び順変更処理", "開始");

		ModelAndView modelAndView = loginController.checkLogin(OWN_TITLE, redirectAttributes);

		if (modelAndView != null) {
			return modelAndView;// ログイン画面へ遷移
		} else {
			modelAndView = new ModelAndView();
		};

		// 検索
		try {
			// 検索結果件数チェック不要
			form.setCountCheck("OK");
			// 1頁目を表示
			form.setPageNo("1");
			form.setInvUserFlg("OFF");	// 退職者は含まない
			// 検索実行
			userListGeneralService.selectUserList(form);

		} catch (Exception e) {

			LogService.system(OWN_TITLE, this.getClass().getSimpleName(), "利用者一覧検索処理", "失敗した");
			LogService.system(ExceptionUtils.getStackTrace(e));
			form.setErrMessage(ms.getMessage("ERR001", null, null));
			modelAndView.addObject(form.getClass().getSimpleName(), form);
			modelAndView.setViewName(OWN_PAGE);
			LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者一覧検索処理", "異常終了");
			return modelAndView;
		}

		// 最大件数リスト取得
		form.setUserMaxCntList(getMaxCntList());

		modelAndView.addObject(form.getClass().getSimpleName(), form);
		modelAndView.setViewName(OWN_PAGE);
		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "利用者一覧並び順変更処理", "正常終了");

		return modelAndView;
	}

	/**
	 * フォーム情報初期化
	 *
	 * @param form フォーム情報
	 * @throws UnsupportedEncodingException
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
		form.setInvUserFlg("OFF");
	}

	/**
	 * ページ件数一覧を取得する
	 *
	 * @return
	 */
	private List<UserMaxCntDto> getMaxCntList() {
		// 最大件数リスト取得
	   	List<UserMaxCntDto> codeValueDtolist =  new ArrayList<UserMaxCntDto>();
    	String[] values = maxCntList.split(",");
    	for(int i =0;i< values.length;i++) {
    		UserMaxCntDto codeValueDto =new UserMaxCntDto();
    		codeValueDto.setCntValue(values[i]);
			codeValueDto.setCntName(values[i]);

			codeValueDtolist.add(codeValueDto);
    	}

    	return codeValueDtolist;
	}
}
