package jp.co.axio.masterMentsetSystem.controller;

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
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import jp.co.axio.masterMentsetSystem.common.CheckDateFormat;
import jp.co.axio.masterMentsetSystem.common.LogService;
import jp.co.axio.masterMentsetSystem.model.MGroupEntity;
import jp.co.axio.masterMentsetSystem.service.SecurityGrpRegService;
import jp.co.axio.masterMentsetSystem.service.SecurityGrpSetService;

@Controller
public class SecurityGrpRegController extends accessController {

  /** 自画面のHTMLテンプレート */
  private static final String OWN_PAGE = "SecurityGrpSet/securityGrpReg";

  /** 初期ページ */
  private final String REDIRECT_PAGE = "redirect:./securityGrpReg";

  /** 自画面のタイトル */
  public static final String OWN_TITLE = "セキュリティグループ登録画面";

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
  SecurityGrpRegService securityGrpRegService;

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
   */
  @RequestMapping("/securityGrpReg")
  public ModelAndView index(@ModelAttribute("SecurityGrpRegForm") SecurityGrpRegForm form,
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

    SecurityGrpRegForm redirectForm = (SecurityGrpRegForm) session.getAttribute(form.getClass().getSimpleName());

    if (redirectForm == null) {
      // アクセストークン設定 二重送信防止
      saveAccessToken(form);
      redirectForm = securityGrpRegService.resetValue(form);
    } else {
      session.removeAttribute(form.getClass().getSimpleName());
      BeanUtils.copyProperties(redirectForm, form);

    }

    modelAndView.addObject(form.getClass().getSimpleName(), redirectForm);
    modelAndView.setViewName(OWN_PAGE);

    LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "初期処理", "正常終了");

    return modelAndView;
  }

  /**
   * 再描画
   *
   * @param form          フォーム情報
   * @param requestParams リクエストパラメータ
   * @return ModelAndView 画面,フォーム情報
   */
  @RequestMapping("/securityGrpRegRedraw")
  public ModelAndView redraw(@ModelAttribute("SecurityGrpRegForm") SecurityGrpRegForm form,
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

    SecurityGrpRegForm redirectForm = (SecurityGrpRegForm) session.getAttribute(form.getClass().getSimpleName());

    String securityGroupCode = form.getSelectSecurityGrpCode();
    if (redirectForm == null) {
      // アクセストークン設定 二重送信防止
      saveAccessToken(form);
      redirectForm = securityGrpRegService.resetValue(form);
    } else {
      session.removeAttribute(form.getClass().getSimpleName());
      BeanUtils.copyProperties(redirectForm, form);
    }

    // 送られてきたセキュリティグループコードからSG組織マスタの値を取得
    // フォームに設定
    try {
      redirectForm = securityGrpRegService.selectRegById(securityGroupCode, redirectForm);
    } catch (Exception e) {
      LogService.system(OWN_TITLE, this.getClass().getSimpleName(), "再描画処理",
          "失敗");
      LogService.system(ExceptionUtils.getStackTrace(e));
      String msg = ms.getMessage("ERR001", null, null);
      form.setErrMessage(msg);
      LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "再描画処理",
          "異常終了");
      return modelAndView;
    }

    modelAndView.addObject(form.getClass().getSimpleName(), redirectForm);
    modelAndView.setViewName(OWN_PAGE);

    LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "再描画処理", "正常終了");

    return modelAndView;
  }

  /**
   * 登録ボタン押下処理
   *
   * @param form          フォーム情報
   * @param requestParams リクエストパラメータ
   * @return ModelAndView 画面,フォーム情報
   *
   */
  @RequestMapping("/securityGrpRegSave")
  public ModelAndView save(@ModelAttribute("SecurityGrpRegForm") @Validated SecurityGrpRegForm form,
      BindingResult result, Model model, RedirectAttributes redirectAttributes) {

    LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "登録ボタン押下処理", "開始");

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

    try {

      // 項目エラーチェック
      // グループテーブル必須確認
      if (form.getSelectSecurityGrpCode().isBlank()
          && !securityGrpRegService.checkRequiredGroup(form.getSecurityGrpBaseList())) {
        String errmsg = ms.getMessage("MSTO0015M0201", null, null);
        result.rejectValue("securityGrpBaseList", "validation.invalid-grouptable", errmsg);
      }

      // 開始日、終了日
      if (!CheckDateFormat.checkDateYMD(form.getStartDate()) || StringUtils.isBlank(form.getStartDate())
          || !CheckDateFormat.checkDateYMD(form.getEndDate()) || StringUtils.isBlank(form.getEndDate())) {
        String errmsg = ms.getMessage("MSTO0015M0202", null, null);
        result.rejectValue("startDate", "validation.invalid-date", errmsg);
      }

      // 項目エラーの場合
      if (result.hasErrors()) {
        modelAndView.addObject(form.getClass().getSimpleName(), form);
        modelAndView.setViewName(OWN_PAGE);
        return modelAndView;
      }

      // 同じグループ名で設定しているか確認

      // グループ名重複確認済みか
      if (!form.getWanCheck().equals("1")) {
        // グループ名重複確認済みでない場合
        // グループ名重複フラグ
        Boolean groupNameDupFlag = false;
        List<String> duplicateGroupName = new ArrayList<>();

        for (SecurityGrpBaseParam sgbp : form.getSecurityGrpBaseList()) {
          Integer duplicatedGroupNameCount = 0;
          duplicatedGroupNameCount = securityGrpRegService.countAdGroupName(sgbp.getGroupName());
          if (duplicatedGroupNameCount > 1) {
            // 重複があった場合
            groupNameDupFlag = true;
            duplicateGroupName.add(sgbp.getGroupName());
          }
        }

        // グループ名重複確認
        if (groupNameDupFlag) {
          // 重複
          String msg = ms.getMessage("MSTO0015M0203", new String[] { String.join("、", duplicateGroupName) },
              null);
          form.setWanMessage(msg);
          form.setWanCheck("1");
          form.setWanUrl("./securityGrpRegSave");
          modelAndView.addObject("SecurityGrpRegForm", form);
          modelAndView.setViewName(OWN_PAGE);

          return modelAndView;
        }
      } else {
        // 組織重複が確認済みの場合
        form.setWanCheck("0");
      }


      // 設定有無確認
      if (form.getSelectSecurityGrpCode().isBlank()) {
        // 設定がない場合
        // 登録
        String newSecurityGroupCode = securityGrpRegService.insertAdGroup(form);
        form.setSelectSecurityGrpCode(newSecurityGroupCode);
      } else {
        // 設定がある場合
        // 更新
        securityGrpRegService.updateAdGroup(form);
      }

      // 完了メッセージ
      String msg = ms.getMessage("CMN0003", new String[] { "組織セキュリティグループの登録" }, null);
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
      modelAndView.addObject("SecurityGrpRegForm", form);
      modelAndView.setViewName(OWN_PAGE);
    }

    // 新しいアクセストークン設定
    saveAccessToken(form);

    modelAndView.addObject(form.getClass().getSimpleName(), form);
    modelAndView.setViewName(OWN_PAGE);

    LogService.info(OWN_TITLE, "SecurityGrpRegController", "登録ボタン押下処理", "正常終了");
    return modelAndView;
  }

  /**
   * 組織SG無効処理
   *
   * @param form
   * @param model
   * @param redirectAttributes
   * @return
   */
  @RequestMapping("/securityGrpRegInvalid")
  public ModelAndView invalid(SecurityGrpRegForm form, Model model,
      RedirectAttributes redirectAttributes) {

    LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "グループ無効ボタン押下処理", "開始");

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
      LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "グループ無効ボタン押下処理",
          "二重送信チェックエラー終了");
      return modelAndView;
    }

    try {

      // 無効
      securityGrpRegService.invalidAdGroup(form.getSelectSecurityGrpCode());

      // 画面項目を初期化
      securityGrpRegService.resetValue(form);

      // 完了メッセージ
      String msg = ms.getMessage("CMN0003", new String[] { "組織セキュリティグループの無効" }, null);
      model.addAttribute("axioMessage", msg);

    } catch (Exception e) {
      LogService.system(OWN_TITLE, this.getClass().getSimpleName(), "グループ無効ボタン押下処理",
          "失敗");
      LogService.system(ExceptionUtils.getStackTrace(e));
      String msg = ms.getMessage("ERR001", null, null);
      form.setErrMessage(msg);
      LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "グループ無効ボタン押下処理",
          "異常終了");
      return modelAndView;
    } finally {
      modelAndView.addObject("SecurityGrpRegForm", form);
      modelAndView.setViewName(OWN_PAGE);
    }

    // 新しいアクセストークン設定
    saveAccessToken(form);

    modelAndView.addObject(form.getClass().getSimpleName(), form);
    modelAndView.setViewName(OWN_PAGE);

    LogService.info(OWN_TITLE, "SecurityGrpRegController", "グループ無効ボタン押下処理", "正常終了");
    return modelAndView;
  }

}
