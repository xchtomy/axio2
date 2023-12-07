package jp.co.axio.masterMentsetSystem.controller;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import javax.servlet.http.HttpSession;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import jp.co.axio.masterMentsetSystem.common.CheckDateFormat;
import jp.co.axio.masterMentsetSystem.common.LogService;
import jp.co.axio.masterMentsetSystem.model.MOrganizationAdGroupEntity;
import jp.co.axio.masterMentsetSystem.service.SecurityGrpSetService;

/**
 * セキュリティグループ登録画面
 *
 * @author axio
 * @version 1.0
 */
@Controller
public class SecurityGrpSetController extends accessController {

	/** 自画面のHTMLテンプレート */
	private static final String OWN_PAGE = "SecurityGrpSet/securityGrpSet";

	/** 初期ページ */
	private final String REDIRECT_PAGE = "redirect:./securityGrpSet";

	/** 自画面のタイトル */
	public static final String OWN_TITLE = "セキュリティグループ編集画面";

	/** パラメータcallParameterに格納されているデータのキー（会社コード） */
	public static final String CALL_PARAMETER_DATA_KEY1 = "companyCode";

	/** パラメータcallParameterに格納されているデータのキー（組織コード） */
	public static final String CALL_PARAMETER_DATA_KEY2 = "organizationCode";

	/** ログインコントローラ */
	@Autowired
	LoginController loginController;

	@Autowired
	SecurityGrpSetService securityGrpSetService;

	@Autowired
	MessageSource ms;

	@Autowired
	HttpSession session;

	/** プロパティファイル グループID採番の頭綴り */
	@Value("${config.group.idPrefix}")
	private String idPrefix;

	/** プロパティファイル グループID採番の桁数 */
	@Value("${config.group.idNumLength:4}")
	private String idNumLength;

	// ログイン情報
	private static final String LOGIN_FORM_SESSION_KEY = "LoginController.loginInfo";

	/**
	 * 初期処理
	 *
	 * @param form          フォーム情報
	 * @param requestParams リクエストパラメータ
	 * @return ModelAndView 画面,フォーム情報
	 * @throws ParseException
	 */
	@RequestMapping("/securityGrpSet")
	public ModelAndView index(@ModelAttribute("SecurityGrpSetForm") SecurityGrpSetForm form,
			RedirectAttributes redirectAttributes) {
		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "初期処理", "開始");

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

		SecurityGrpSetForm redirectForm = (SecurityGrpSetForm) session.getAttribute(form.getClass().getSimpleName());

		// 組織設定済みセキュリティグループ
		List<SecurityGrpBaseParam> securityGroupNotSetting = new ArrayList<>();
		// 組織未設セキュリティグループ
		List<SecurityGrpBaseParam> securityGroupSetting = new ArrayList<>();

		if (redirectForm == null) {
			// アクセストークン設定 二重送信防止
			saveAccessToken(form);
			securityGrpSetService.resetValue(form);

			try {
				// 未設定セキュリティグループを取得
				securityGroupNotSetting = securityGrpSetService.selectNotSetting();

				// 設定済みセキュリティグループを取得
				securityGroupSetting = securityGrpSetService.selectSetting();

			} catch (ParseException e) {
				// 取得に失敗した場合、null
				LogService.system(ExceptionUtils.getStackTrace(e));
				securityGroupSetting = null;
				securityGroupNotSetting = null;
			}

		} else {
			session.removeAttribute(form.getClass().getSimpleName());
			BeanUtils.copyProperties(redirectForm, form);

		}

		modelAndView.addObject(form.getClass().getSimpleName(), form);
		modelAndView.addObject("securityGroupNotSetting", securityGroupNotSetting);
		modelAndView.addObject("securityGroupSetting", securityGroupSetting);
		modelAndView.setViewName(OWN_PAGE);

		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "初期処理", "正常終了");

		return modelAndView;
	}

	/**
	 * 画面設定処理（組織コード一覧画面からの戻り）
	 *
	 * @param form フォーム情報
	 * @return securityGrpSetDto セキュリティグループ情報
	 * @throws Exception
	 */
	@RequestMapping("/securityGrpSetRedraw")
	@ResponseBody
	public ModelAndView redraw(@ModelAttribute("SecurityGrpSetForm") SecurityGrpSetForm form,
			RedirectAttributes redirectAttributes) {
		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "画面設定処理", "開始");

		ModelAndView modelAndView = loginController.checkLogin(OWN_TITLE, redirectAttributes);
		SecurityGrpSetForm redirectForm = new SecurityGrpSetForm();

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

		// 組織SGIDから取得
		List<MOrganizationAdGroupEntity> entity = null;
		// 組織未設定セキュリティグループ
		List<SecurityGrpBaseParam> securityGroupNotSetting = new ArrayList<>();
		// 組織設定済みセキュリティグループ
		List<SecurityGrpBaseParam> securityGroupSetting = new ArrayList<>();

		try {
			// 表の設定値取得
			entity = securityGrpSetService.selectBaseParam(form.getSelectSecurityGrpCode());

			// 存在していない場合
			if (entity == null) {
				String msg = ms.getMessage("MSTO0014M0001", null, null);
				form.setErrMessage(msg);

				LogService.system(OWN_TITLE, this.getClass().getSimpleName(),
						"該当するセキュリティグループ情報は存在しません。 (セキュリティグループコード : " + form.getSelectSecurityGrpCode() + ")",
						"異常終了");

				// 画面項目を初期化
				redirectForm = securityGrpSetService.resetValue(form);
			} else {
				// 画面項目を設定
				redirectForm = securityGrpSetService.setForm(form, entity);

				// 未設定セキュリティグループを取得
				securityGroupNotSetting = securityGrpSetService.selectNotSetting();

				// 設定済みセキュリティグループを取得
				securityGroupSetting = securityGrpSetService.selectSetting();
			}

		} catch (Exception e) {
			LogService.system(ExceptionUtils.getStackTrace(e));
			LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "画面設定処理", "異常終了");
			return modelAndView;
		}

		modelAndView.addObject(form.getClass().getSimpleName(), redirectForm);
		modelAndView.addObject("securityGroupNotSetting", securityGroupNotSetting);
		modelAndView.addObject("securityGroupSetting", securityGroupSetting);
		modelAndView.setViewName(OWN_PAGE);

		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "画面設定処理", "正常終了");
		return modelAndView;
	}

	/**
	 * 設定済みセキュリティグループの取得
	 * 未設定セキュリティグループの取得
	 *
	 * @param choiceData
	 * @param redirectAttributes
	 * @return
	 * @throws Exception
	 */
	@PostMapping("/securityGrpSetSelect")
	@ResponseBody
	public ModelAndView selectSecurityGrp(@ModelAttribute("SecurityGrpSetForm") SecurityGrpSetForm form,
			RedirectAttributes redirectAttributes) throws Exception {

		ModelAndView modelAndView = loginController.checkLogin(OWN_TITLE, redirectAttributes);
		SecurityGrpSetForm redirectForm = new SecurityGrpSetForm();

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

		// 組織SGIDから取得
		List<MOrganizationAdGroupEntity> entity = null;
		// 組織未設定セキュリティグループ
		List<SecurityGrpBaseParam> securityGroupNotSetting = new ArrayList<>();
		// 組織設定済みセキュリティグループ
		List<SecurityGrpBaseParam> securityGroupSetting = new ArrayList<>();

		try {

			entity = securityGrpSetService.selectBaseParam(form.getSelectSecurityGrpCode());

			if (entity == null) {
				String msg = ms.getMessage("MSTO0014M0001", null, null);
				form.setErrMessage(msg);

				LogService.system(OWN_TITLE, this.getClass().getSimpleName(),
						"該当するセキュリティグループ情報は存在しません。(" + form.getSelectSecurityGrpCode() + ")", "異常終了");

				// 画面項目を初期化
				securityGrpSetService.resetValue(form);

				// 未設定セキュリティグループを取得
				securityGroupNotSetting = securityGrpSetService.selectNotSetting();

				// 設定済みセキュリティグループを取得
				securityGroupSetting = securityGrpSetService.selectSetting();

			} else {
				// フォーム設定
				redirectForm = securityGrpSetService.setForm(form, entity);

				// 未設定セキュリティグループを取得
				securityGroupNotSetting = securityGrpSetService.selectNotSetting();

				// 設定済みセキュリティグループを取得
				securityGroupSetting = securityGrpSetService.selectSetting();

			}
		} catch (Exception e) {
			LogService.system(ExceptionUtils.getStackTrace(e));
			LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "画面設定処理", "異常終了");
			return modelAndView;
		}

		modelAndView.addObject(form.getClass().getSimpleName(), redirectForm);
		modelAndView.addObject("securityGroupNotSetting", securityGroupNotSetting);
		modelAndView.addObject("securityGroupSetting", securityGroupSetting);
		modelAndView.setViewName(OWN_PAGE);

		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "画面設定処理", "正常終了");
		return modelAndView;

	}

	/**
	 * 登録ボタン押下処理
	 *
	 * @param form          フォーム情報
	 * @param requestParams リクエストパラメータ
	 * @return ModelAndView 画面,フォーム情報
	 * @throws ParseException
	 *
	 */
	@RequestMapping("/securityGrpSetSave")
	public ModelAndView save(@ModelAttribute("SecurityGrpSetForm") @Validated SecurityGrpSetForm form,
			BindingResult result, Model model,
			RedirectAttributes redirectAttributes) throws ParseException {
		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "登録ボタン押下処理",
				"開始");

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

		// 二重送信、ページ不正アクセス防止
		if (!checkAccessToken(form)) {
			modelAndView.setViewName(REDIRECT_PAGE);
			LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "登録ボタン押下処理",
					"二重送信チェックエラー終了");
			return modelAndView;
		}

		// 組織未設定セキュリティグループ
		List<SecurityGrpBaseParam> securityGroupNotSetting = new ArrayList<>();
		// 組織設定済みセキュリティグループ
		List<SecurityGrpBaseParam> securityGroupSetting = new ArrayList<>();

		try {

			// 項目エラーチェック
			// 組織選択
			if (!securityGrpSetService.checkOrganizasion(form.getCompanyCode(), form.getOrganizationCode())) {
				String errmsg = ms.getMessage("MSTO0015M0101", null, null);
				result.rejectValue("organizationCode", "validation.invalid-organization", errmsg);
			}

			// 反映日
			if (!CheckDateFormat.checkDateYMD(form.getReflectionDate())
					|| StringUtils.isBlank(form.getReflectionDate())) {
				String errmsg = ms.getMessage("MSTO0015M0102", null, null);
				result.rejectValue("reflectionDate", "validation.invalid-date", errmsg);
			}

			// 項目エラーの場合
			if (result.hasErrors()) {
				modelAndView.addObject(form.getClass().getSimpleName(), form);
				modelAndView.addObject("securityGroupNotSetting", securityGroupNotSetting);
				modelAndView.addObject("securityGroupSetting", securityGroupSetting);
				modelAndView.setViewName(OWN_PAGE);
				return modelAndView;
			}


			// 組織重複確認済みか
			if (!form.getWanCheck().equals("1")) {
				// 組織重複確認済みでない場合
				// 組織重複確認
				if (securityGrpSetService.checkDuplicatedOrganization(form)) {
					// 重複
					String msg = ms.getMessage("MSTO0015M0103", new String[] { form.getOrganizationName() },
					null);
					form.setWanMessage(msg);
					form.setWanCheck("1");
					form.setWanUrl("./securityGrpSetSave");
					modelAndView.addObject("SecurityGrpSetForm", form);
					modelAndView.setViewName(OWN_PAGE);

					return modelAndView;
				}
			} else {
				// 組織重複が確認済みの場合
				form.setWanCheck("0");
			}

			// 既存設定取得
			MOrganizationAdGroupEntity entity = new MOrganizationAdGroupEntity();
			entity = securityGrpSetService.selectOrganizationAdGroup(form);

			// 設定有無確認
			if (Objects.isNull(entity)) {
				// 設定がない場合
				// 登録
				securityGrpSetService.insertOrganizationAdGroup(form);

			} else {
				// 設定がある場合
				// 既存
				// 更新
				securityGrpSetService.updateOrganizationAdGroup(form, entity);
			}

			// 未設定セキュリティグループを取得
			securityGroupNotSetting = securityGrpSetService.selectNotSetting();

			// 設定済みセキュリティグループを取得
			securityGroupSetting = securityGrpSetService.selectSetting();

			// 完了メッセージ
			String msg = ms.getMessage("CMN0003", new String[] { "組織セキュリティグループの設定" },
					null);
			model.addAttribute("axioMessage", msg);

		} catch (Exception e) {
			LogService.system(OWN_TITLE, this.getClass().getSimpleName(), "登録ボタン押下処理",
					"失敗");
			LogService.system(ExceptionUtils.getStackTrace(e));
			String msg = ms.getMessage("ERR001", null, null);
			form.setErrMessage(msg);
			LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "登録ボタン押下処理",
					"異常終了");
			return modelAndView;
		} finally {
			modelAndView.addObject("SecurityGrpSetForm", form);
			modelAndView.setViewName(OWN_PAGE);
		}

		// 新しいアクセストークン設定
		saveAccessToken(form);
		modelAndView.addObject(form.getClass().getSimpleName(), form);
		modelAndView.addObject("securityGroupNotSetting", securityGroupNotSetting);
		modelAndView.addObject("securityGroupSetting", securityGroupSetting);
		modelAndView.setViewName(OWN_PAGE);

		LogService.info(OWN_TITLE, "SecurityGrpSetController", "登録ボタン押下処理", "正常終了");
		return modelAndView;
	}


	/**
	 * 紐づき解除
	 *
	 * @param form フォーム情報
	 * @return securityGrpSetDto セキュリティグループ情報
	 * @throws Exception
	 */
	@RequestMapping("/securityGrpSetClear")
	@ResponseBody
	public ModelAndView clear(@ModelAttribute("SecurityGrpSetForm") SecurityGrpSetForm form,
		Model model,RedirectAttributes redirectAttributes) {
		
		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "画面設定処理", "開始");

		ModelAndView modelAndView = loginController.checkLogin(OWN_TITLE, redirectAttributes);
		SecurityGrpSetForm redirectForm = new SecurityGrpSetForm();

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

		// 組織SGIDから取得
		List<MOrganizationAdGroupEntity> entity = null;
		// 組織未設定セキュリティグループ
		List<SecurityGrpBaseParam> securityGroupNotSetting = new ArrayList<>();
		// 組織設定済みセキュリティグループ
		List<SecurityGrpBaseParam> securityGroupSetting = new ArrayList<>();

		try {
			// 表の設定値取得
			entity = securityGrpSetService.selectBaseParam(form.getSelectSecurityGrpCode());

			// 存在していない場合
			if (entity == null) {
				String msg = ms.getMessage("MSTO0014M0001", null, null);
				form.setErrMessage(msg);

				LogService.system(OWN_TITLE, this.getClass().getSimpleName(),
						"該当するセキュリティグループ情報は存在しません。 (セキュリティグループコード : " + form.getSelectSecurityGrpCode() + ")",
						"異常終了");

				// 画面項目を初期化
				redirectForm = securityGrpSetService.resetValue(form);
			} else {

				// 既存設定取得
				MOrganizationAdGroupEntity orgAdGroup = new MOrganizationAdGroupEntity();
				orgAdGroup = securityGrpSetService.selectOrganizationAdGroup(form);

				// 紐づき設定無効化
				securityGrpSetService.clear(orgAdGroup);

				// フォームクリア
				redirectForm = securityGrpSetService.resetValue(form);

				// 未設定セキュリティグループを取得
				securityGroupNotSetting = securityGrpSetService.selectNotSetting();

				// 設定済みセキュリティグループを取得
				securityGroupSetting = securityGrpSetService.selectSetting();
			}

		} catch (Exception e) {
			LogService.system(ExceptionUtils.getStackTrace(e));
			LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "画面設定処理", "異常終了");
			return modelAndView;
		}

		modelAndView.addObject(form.getClass().getSimpleName(), redirectForm);
		modelAndView.addObject("securityGroupNotSetting", securityGroupNotSetting);
		modelAndView.addObject("securityGroupSetting", securityGroupSetting);
		modelAndView.setViewName(OWN_PAGE);

		// 完了メッセージ
		String msg = ms.getMessage("CMN0003", new String[] { "組織セキュリティグループの紐づけ解除" },null);
		model.addAttribute("axioMessage", msg);

		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "画面設定処理", "正常終了");
		return modelAndView;
	}


}