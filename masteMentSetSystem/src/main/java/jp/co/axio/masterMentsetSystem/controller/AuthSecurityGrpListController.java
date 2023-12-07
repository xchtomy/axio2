package jp.co.axio.masterMentsetSystem.controller;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import jp.co.axio.masterMentsetSystem.common.CheckDateFormat;
import jp.co.axio.masterMentsetSystem.common.LogService;
import jp.co.axio.masterMentsetSystem.dto.AuthGroupListDto;
import jp.co.axio.masterMentsetSystem.dto.AuthSecurityGrpListDto;
import jp.co.axio.masterMentsetSystem.model.MGroupEntity;
import jp.co.axio.masterMentsetSystem.model.MOrganizationAdGroupEntity;
import jp.co.axio.masterMentsetSystem.service.AuthGroupListService;
import jp.co.axio.masterMentsetSystem.service.AuthSecurityGrpListService;

@Controller
public class AuthSecurityGrpListController {

  /** 自画面のHTMLテンプレート */
  private final String OWN_PAGE = "SecurityGrpSet/authSecurityGrpList";

  /** 自処理対象画面名 */
  private static final String OWN_TITLE = "グループ一覧画面";

  /** ログインコントローラ */
  @Autowired
  LoginController loginController;

  @Autowired
  AuthSecurityGrpListService authSecurityGrpListService;

  @Autowired
  MessageSource ms;

  /**
   * 初期処理
   *
   * @throws Exception
   *
   */
  @RequestMapping("/authSecurityGroupList")
  public ModelAndView index(@ModelAttribute("AuthSecurityGrpListForm") AuthSecurityGrpListForm form,
      BindingResult result,
      HttpServletRequest request, RedirectAttributes redirectAttributes) {
    LogService.info("グループ検索一覧画面", "AuthGroupListController", "初期処理", "開始");

    /**
     * 2022/02/07 ログインチェック追加 開始
     */
    // 既存処理コメントアウト
    // ModelAndView modelAndView = new ModelAndView();

    ModelAndView modelAndView = loginController.checkLogin(OWN_TITLE, redirectAttributes);
    if (modelAndView != null) {
      return modelAndView;// ログイン画面へ遷移
    } else {
      modelAndView = new ModelAndView();
    }
    /**
     * 2022/02/07 ログインチェック追加 終了
     */

    modelAndView.addObject("AuthSecurityGrpListForm", form);

    // パラメータをフォームに格納する
    form.setDailogCallFrom(form.getCallFrom());
    form.setDailogCallParameter(form.getCallParameter());

    // デフォルート有効基準日をセット
    form.setDailogStartDate(new SimpleDateFormat("yyyy/MM/dd").format(new Date()));

    try {
      List<String> chkCodes = form.getListCheck();
      List<AuthSecurityGrpListDto> ilist = new ArrayList<>();
      String json = form.getDailogCallParameter();

      if (StringUtils.isNotBlank(json)) {
        JsonElement jelement = new JsonParser().parse(json);
        JsonArray jarray = jelement != null ? jelement.getAsJsonArray() : null;
        if (jarray != null && jarray.size() > 0) {
          // groupId = jarray.get(0).getAsJsonObject().get("groupId").getAsString();
          if (chkCodes == null) {
            chkCodes = new ArrayList<String>();
            form.setListCheck(chkCodes);
          }
          for (int i = 0; i < jarray.size(); i++) {
            String securityGroupCode = jarray.get(i).getAsJsonObject().get("securityGroupCode").getAsString();
            // チェックグループID追加
            chkCodes.add(securityGroupCode);
            // 上部グループ情報検索
            // List<AuthSecurityGrpListDto> mlist =
            // getGroupConditionSetDtoList(securityGroupCode);
            // 上部グループ情報にマージ
            // ilist = editGroupInfoDtoList(mlist, ilist, true, chkCodes);
          }
        }
      }
      form.setListGroupItems(ilist);

    } catch (Exception e) {
      LogService.system("グループ検索一覧画面", "AuthGroupListController", "初期処理", "失敗した");
      LogService.system(ExceptionUtils.getStackTrace(e));
      String msg = ms.getMessage("ERR001", null, null);
      form.setDailogErrMessage(msg);
      LogService.info("グループ検索一覧画面", "AuthGroupListController", "初期処理", "··異常終了");
      return modelAndView;
    } finally {
      modelAndView.addObject("AuthGroupListForm", form);
      modelAndView.setViewName(OWN_PAGE);
    }

    modelAndView.setViewName(OWN_PAGE);
    LogService.info("グループ検索一覧画面", "AuthGroupListController", "初期処理", "正常終了");
    return modelAndView;
  }

  /**
   * 検索処理
   *
   * @throws Exception
   *
   */
  @RequestMapping("/authSecurityGroupListSearch")
  public ModelAndView search(@ModelAttribute("AuthSecurityGrpListForm") AuthSecurityGrpListForm form,
      BindingResult result, HttpServletRequest request) {
    LogService.info("グループ検索一覧画面", "AuthGroupListController", "検索処理", "開始");
    ModelAndView modelAndView = new ModelAndView();

    // 入力の有効基準日のフォーマットチェック
    if (!CheckDateFormat.checkDateYMD(form.getDailogStartDate())) {

      List<AuthSecurityGrpListDto> list = new ArrayList<>();
      form.setListGroupItems(list);
      form.setDailogErrMessage(ms.getMessage("CMN0008", null, null));
      modelAndView.addObject("AuthGroupListForm", form);
      modelAndView.setViewName(OWN_PAGE);
      LogService.info("グループ検索一覧画面", "AuthGroupListController", "検索処理", "正常終了");
      return modelAndView;
    }

    try {

      // 入力値によりグループ検索
      List<AuthSecurityGrpListDto> asgList = authSecurityGrpListService.selectGroupList(form);
      form.setListGroupItems(asgList);

      if (asgList == null || asgList.isEmpty()) {
        String msg = ms.getMessage("MSTO0006M0007", new String[] { "0" }, null);
        form.setDailogErrMessage(msg);
      }
    } catch (Exception e) {
      LogService.system("グループ検索一覧画面", "AuthGroupListController", "検索処理", "失敗した");
      LogService.system(ExceptionUtils.getStackTrace(e));
      form.setDailogErrMessage(e.getMessage());
      LogService.info("グループ検索一覧画面", "AuthGroupListController", "検索処理", "··異常終了");
      return modelAndView;

    } finally {
      modelAndView.addObject("AuthSecurityGrpListForm", form);
      modelAndView.setViewName(OWN_PAGE);
    }

    LogService.info("グループ検索一覧画面", "AuthGroupListController", "検索処理", "正常終了");
    return modelAndView;
  }


}
