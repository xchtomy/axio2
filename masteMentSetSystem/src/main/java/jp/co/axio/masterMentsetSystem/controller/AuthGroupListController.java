package jp.co.axio.masterMentsetSystem.controller;


import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

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

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

import jp.co.axio.masterMentsetSystem.common.CheckDateFormat;
import jp.co.axio.masterMentsetSystem.common.LogService;
import jp.co.axio.masterMentsetSystem.dto.AuthGroupListDto;
import jp.co.axio.masterMentsetSystem.model.MGroupEntity;
import jp.co.axio.masterMentsetSystem.service.AuthGroupListService;

/**
 * グループ一覧画面
 *
 * @author AXIO
 * @version 1.0
 */
@Controller
public class AuthGroupListController {

    /** 自画面のHTMLテンプレート */
    private final String OWN_PAGE = "AuthGroupSet/authGroupList";

	/** 自処理対象画面名 */
	private static final String OWN_TITLE = "グループ一覧画面";

	/** ログインコントローラ */
	@Autowired
	LoginController loginController;

    @Autowired
    AuthGroupListService authGroupListService;

    @Autowired
    MessageSource ms;

	/**
	 * 初期処理
	 *
	 * @throws Exception
	 *
	 */
	@RequestMapping("/authGroupList")
	public ModelAndView index(@ModelAttribute("AuthGroupListForm") AuthGroupListForm form, BindingResult result, HttpServletRequest request, RedirectAttributes redirectAttributes)  {
		LogService.info("グループ検索一覧画面", "AuthGroupListController", "初期処理", "開始");

		/**
		 * 2022/02/07　ログインチェック追加 開始
		 */
		// 既存処理コメントアウト
		// ModelAndView modelAndView = new ModelAndView();

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
		 * 2022/02/07　ログインチェック追加 終了
		 */

		modelAndView.addObject("AuthGroupListForm", form);

		//パラメータをフォームに格納する
		form.setDailogCallFrom(form.getCallFrom());
		form.setDailogCallParameter(form.getCallParameter());

		//デフォルート有効基準日をセット
		form.setDailogStartDate(new SimpleDateFormat("yyyy/MM/dd").format(new Date()));

		try {
			List<String> chkCodes = form.getListCheck();
        	List<AuthGroupListDto> ilist = new ArrayList<AuthGroupListDto>();
			String json = form.getDailogCallParameter();
			if (StringUtils.isNotBlank(json)) {
		        JsonElement jelement  = new JsonParser().parse(json);
		        JsonArray  jarray = jelement != null ? jelement.getAsJsonArray() : null;
		        if (jarray != null && jarray.size() > 0) {
			        //groupId = jarray.get(0).getAsJsonObject().get("groupId").getAsString();
		        	if (chkCodes == null) {
		        		chkCodes = new ArrayList<String>();
		        		form.setListCheck(chkCodes);
		        	}
		        	for (int i = 0; i < jarray.size(); i++) {
		        		String groupId = jarray.get(i).getAsJsonObject().get("groupId").getAsString();
		        		//チェックグループID追加
		        		chkCodes.add(groupId);
			        	//上部グループ情報検索
			        	List<AuthGroupListDto> mlist = getGroupConditionSetDtoList(groupId);
			        	//上部グループ情報にマージ
			        	ilist = editGroupInfoDtoList(mlist, ilist, true, chkCodes);
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
	@RequestMapping("/authGroupListSearch")
	public ModelAndView search(@ModelAttribute("AuthGroupListForm") AuthGroupListForm form, BindingResult result, HttpServletRequest request)  {
		LogService.info("グループ検索一覧画面", "AuthGroupListController", "検索処理", "開始");
		ModelAndView modelAndView = new ModelAndView();

		//入力の有効基準日のフォーマットチェック
		if (!CheckDateFormat.checkDateYMD(form.getDailogStartDate())) {

			List<AuthGroupListDto> list = new ArrayList<AuthGroupListDto>();
			form.setListGroupItems(list);
			form.setDailogErrMessage(ms.getMessage("CMN0008", null, null));
			modelAndView.addObject("AuthGroupListForm", form);
			modelAndView.setViewName(OWN_PAGE);
			LogService.info("グループ検索一覧画面", "AuthGroupListController", "検索処理", "正常終了");
			return modelAndView;
		}

		try {
        	List<AuthGroupListDto> ilist = new ArrayList<AuthGroupListDto>();
			String json = form.getDailogCallParameter();
			if (StringUtils.isNotBlank(json)) {
		        JsonElement jelement  = new JsonParser().parse(json);
		        JsonArray  jarray =  jelement.getAsJsonArray();
		        if (jarray.size() > 0) {
			        //groupId = jarray.get(0).getAsJsonObject().get("groupId").getAsString();
		        	for (int i = 0; i < jarray.size(); i++) {
		        		String groupId = jarray.get(i).getAsJsonObject().get("groupId").getAsString();
			        	//上部グループ情報検索
			        	List<AuthGroupListDto> mlist = getGroupConditionSetDtoList(groupId);

			        	//上部グループ情報にマージ
			        	ilist = editGroupInfoDtoList(mlist, ilist, true, form.getListCheck());
		        	}
		        }
			}

	        //入力値によりグループ検索
	        List<AuthGroupListDto> rlist =  authGroupListService.selectGroupList(form);
	        ilist = editGroupInfoDtoList(rlist, ilist, false, form.getListCheck());
        	form.setListGroupItems(ilist);

	        if (rlist == null || rlist.isEmpty()) {
	        	String msg = ms.getMessage("MSTO0006M0007", new String[] {"0"}, null );
	        	form.setDailogErrMessage(msg);
	        }
		} catch (Exception e) {
			LogService.system("グループ検索一覧画面", "AuthGroupListController", "検索処理", "失敗した");
			LogService.system(ExceptionUtils.getStackTrace(e));
			form.setDailogErrMessage(e.getMessage());
			LogService.info("グループ検索一覧画面", "AuthGroupListController", "検索処理", "··異常終了");
			return modelAndView;

		} finally {
			modelAndView.addObject("AuthGroupListForm", form);
			modelAndView.setViewName(OWN_PAGE);
		}

		LogService.info("グループ検索一覧画面", "AuthGroupListController", "検索処理", "正常終了");
		return modelAndView;
	}

	/**
	 * 渡されたグループIDより情報設定
	 *
	 * @param groupId
	 * @return
	 * @throws Exception
	 */
	public List<AuthGroupListDto> getGroupConditionSetDtoList(String groupId) throws Exception {
    	// 一覧部分の上部・選択済みグループの情報を検索して設定する
    	MGroupEntity mgroup = authGroupListService.selectByGroupId(groupId);
    	SimpleDateFormat df = new SimpleDateFormat("yyyy/MM/dd");

    	//上部グループ情報設定
    	List<AuthGroupListDto> mlist = new ArrayList<AuthGroupListDto>();
    	AuthGroupListDto rdto = new AuthGroupListDto();
    	rdto.setGroupId(mgroup.getGroupId());
    	rdto.setGroupNameEn(mgroup.getGroupNameEn());
    	rdto.setGroupNameJp(mgroup.getGroupNameJp());
    	rdto.setNote(mgroup.getNote());
    	rdto.setStartDate(df.format(mgroup.getStartDate()));
    	rdto.setEndDate(df.format(mgroup.getEndDate()));
    	mlist.add(rdto);

    	return mlist;
	}

	/**
	 * 一覧部の情報設定、マージ
	 *
	 * @param frlist
	 * @param tolist
	 * @param flg
	 * @return
	 */
	public List<AuthGroupListDto> editGroupInfoDtoList(List<AuthGroupListDto> frlist,  List<AuthGroupListDto> tolist,
				boolean flg, List<String> checklist) {
		HashMap<String, String> k = new HashMap<String, String>();
		if (tolist == null) {
			tolist = new ArrayList<AuthGroupListDto>();
		} else {
			for (AuthGroupListDto r : tolist) {
				k.put(r.getGroupId(), r.getGroupId());
			}
		}

		if (frlist != null) {
			for (AuthGroupListDto rs : frlist) {
				if (StringUtils.equals(rs.getGroupId(), k.get(rs.getGroupId()))) {
					continue;
				}
				AuthGroupListDto rl = new AuthGroupListDto();
				String groupId = rs.getGroupId();
				rl.setDispFlag(flg);
				rl.setCheckFlag(checklist!=null&&checklist.contains(groupId)?true:false);
				rl.setGroupId(groupId);
				rl.setGroupNameEn(rs.getGroupNameEn());
				rl.setGroupNameJp(rs.getGroupNameJp());
				rl.setNote(rs.getNote());
				rl.setStartDate(rs.getStartDate());
				rl.setEndDate(rs.getEndDate());
				tolist.add(rl);
			}
		}
		return tolist;
	}

 }


