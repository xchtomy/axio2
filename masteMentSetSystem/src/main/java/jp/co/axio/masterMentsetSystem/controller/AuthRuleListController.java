package jp.co.axio.masterMentsetSystem.controller;


import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

import jp.co.axio.masterMentsetSystem.common.CheckDateFormat;
import jp.co.axio.masterMentsetSystem.common.LogService;
import jp.co.axio.masterMentsetSystem.dto.AuthPosCodeListDto;
import jp.co.axio.masterMentsetSystem.dto.RuleConditionSetDto;
import jp.co.axio.masterMentsetSystem.dto.RuleInfoListDto;
import jp.co.axio.masterMentsetSystem.model.MRuleEntity;
import jp.co.axio.masterMentsetSystem.service.AuthRuleListService;
import jp.co.axio.masterMentsetSystem.service.AuthRuleSetService;

/**
 * ルール検索一覧画面
 *
 * @author JCBC
 * @version 1.0
 */
@Controller
public class AuthRuleListController {

    /** 自画面のHTMLテンプレート */
    private final String OWN_PAGE = "AuthRuleSet/authRuleList";

    /** 初期ページ　*/
    private final String REDIRECT_PAGE = "redirect:./authRuleList";

    @Autowired
    AuthRuleListService authRuleListService;

    @Autowired
    MessageSource ms;

	/**
	 * 初期処理
	 *
	 * @throws Exception
	 *
	 */
	@RequestMapping("/authRuleList")
	public ModelAndView index(@ModelAttribute("AuthRuleListForm") AuthRuleListForm form, BindingResult result, HttpServletRequest request)  {
		LogService.info("ルール検索一覧画面", "AuthRuleListController", "初期処理", "開始");
		ModelAndView modelAndView = new ModelAndView();

		modelAndView.addObject("AuthRuleListForm", form);

		//パラメータをフォームに格納する
		form.setDailogCallFrom(form.getCallFrom());
		form.setDailogCallParameter(form.getCallParameter());

		//デフォルート有効基準日をセット
		form.setDailogStartDate(new SimpleDateFormat("yyyy/MM/dd").format(new Date()));

		try {
			String ruleId = null;
			String json = form.getDailogCallParameter();
			if (StringUtils.isNotBlank(json)) {
		        JsonElement jelement  = new JsonParser().parse(json);
		        JsonArray  jarray =  jelement != null ? jelement.getAsJsonArray() : null;
		        if (jarray != null && jarray.size() > 0) {
		        	ruleId = jarray.get(0).getAsJsonObject().get("ruleId").getAsString();
		        }
			}
	        if (StringUtils.isNotBlank(ruleId)) {
	        	//上部ルール情報検索
	        	List<RuleConditionSetDto> mlist = getRuleConditionSetDtoList(ruleId);
	        	List<String> chkCodes = new ArrayList<String>();
	        	if (mlist != null && mlist.size() > 0) {
	        		form.setCheckRuleId(mlist.get(0).getRuleId());
	        		chkCodes.add(mlist.get(0).getRuleId());
	        		form.setListCheck(chkCodes);
	        	}
	        	//上部ルール情報設定
	        	List<RuleInfoListDto> ilist = editRuleInfoDtoList(mlist, null, true, form.getListCheck());
	        	form.setListRuleItems(ilist);
	        }
		} catch (Exception e) {
			LogService.system("ルール検索一覧画面", "AuthRuleListController", "初期処理", "失敗した");
			LogService.system(ExceptionUtils.getStackTrace(e));
			String msg = ms.getMessage("ERR001", null, null);
			form.setDailogErrMessage(msg);
			LogService.info("ルール検索一覧画面", "AuthRuleListController", "初期処理", "··異常終了");
			return modelAndView;
		} finally {
			modelAndView.addObject("AuthRuleSetForm", form);
			modelAndView.setViewName(OWN_PAGE);
		}

		modelAndView.setViewName(OWN_PAGE);
		LogService.info("ルール検索一覧画面", "AuthRuleListController", "初期処理", "正常終了");
		return modelAndView;
	}

	/**
	 * 検索処理
	 *
	 * @throws Exception
	 *
	 */
	@RequestMapping("/authRuleListSearch")
	public ModelAndView search(@ModelAttribute("AuthRuleListForm") AuthRuleListForm form, BindingResult result, HttpServletRequest request)  {
		LogService.info("ルール検索一覧画面", "AuthRuleListController", "検索処理", "開始");
		ModelAndView modelAndView = new ModelAndView();

		//入力有効基準日のフォーマットチェック
		if (!CheckDateFormat.checkDateYMD(form.getDailogStartDate())) {

			List<RuleInfoListDto> list = new ArrayList<RuleInfoListDto>();
			form.setListRuleItems(list);
			form.setDailogErrMessage(ms.getMessage("CMN0008", null, null));
			modelAndView.addObject("AuthRuleListForm", form);
			modelAndView.setViewName(OWN_PAGE);
			LogService.info("ルール検索一覧画面", "AuthRuleListController", "検索処理", "正常終了");
			return modelAndView;
		}

		try {
			String ruleId = null;
			String json = form.getDailogCallParameter();
			if (StringUtils.isNotBlank(json)) {
		        JsonElement jelement  = new JsonParser().parse(json);
		        JsonArray  jarray =  jelement != null ? jelement.getAsJsonArray() : null;
		        if (jarray != null && jarray.size() > 0) {
		        	ruleId = jarray.get(0).getAsJsonObject().get("ruleId").getAsString();
		        }
			}

			List<RuleInfoListDto> ilist = null;
	        if (StringUtils.isNotBlank(ruleId)) {
	        	//上部ルール情報検索
	        	List<RuleConditionSetDto> mlist = getRuleConditionSetDtoList(ruleId);

	        	//上部ルール情報設定
	        	ilist = editRuleInfoDtoList(mlist, ilist, true, form.getListCheck());
	        	form.setListRuleItems(ilist);
	        }

	        //入力値によりルール検索
	        List<RuleConditionSetDto> rlist =  authRuleListService.selectRuleList(form);
	        ilist = editRuleInfoDtoList(rlist, ilist, false, form.getListCheck());
        	form.setListRuleItems(ilist);

	        if (rlist == null || rlist.isEmpty()) {
	        	String msg = ms.getMessage("MSTO0007M0007", new String[] {"0"}, null );
	        	form.setDailogErrMessage(msg);
	        }
		} catch (Exception e) {
			LogService.system("ルール検索一覧画面", "AuthRuleListController", "検索処理", "失敗した");
			LogService.system(ExceptionUtils.getStackTrace(e));
			form.setDailogErrMessage(e.getMessage());
			LogService.info("ルール検索一覧画面", "AuthRuleListController", "検索処理", "··異常終了");
			return modelAndView;

		} finally {
			modelAndView.addObject("AuthRuleListForm", form);
			modelAndView.setViewName(OWN_PAGE);
		}

		//modelAndView.setViewName(REDIRECT_PAGE);
		LogService.info("ルール検索一覧画面", "AuthRuleListController", "検索処理", "正常終了");
		return modelAndView;
	}

	public List<RuleConditionSetDto> getRuleConditionSetDtoList(String ruleId) throws Exception {
    	//上部ルール情報検索
    	MRuleEntity mrule = authRuleListService.selectAuthRuleMst(ruleId);
    	SimpleDateFormat df = new SimpleDateFormat("yyyy/MM/dd");

    	//上部ルール情報設定
    	List<RuleConditionSetDto> mlist = new ArrayList<RuleConditionSetDto>();
    	RuleConditionSetDto rdto = new RuleConditionSetDto();
    	mlist.add(rdto);

    	rdto.setRuleId(mrule.getRuleId());
    	rdto.setRuleName(mrule.getRuleName());
    	rdto.setNote(mrule.getNote());
    	rdto.setStartDate(df.format(mrule.getStartDate()));
    	rdto.setEndDate(df.format(mrule.getEndDate()));

    	return mlist;
	}

	public List<RuleInfoListDto> editRuleInfoDtoList(List<RuleConditionSetDto> frlist,  List<RuleInfoListDto> tolist,
				boolean dspflg, List<String> checklist) {

		HashMap<String, String> k = new HashMap<String, String>();
		if (tolist == null) {
			tolist = new ArrayList<RuleInfoListDto>();
		} else {
			for (RuleInfoListDto r : tolist) {
				k.put(r.getRuleId(), r.getRuleId());
			}
		}

		if (frlist != null) {
			for (RuleConditionSetDto rs : frlist) {
				if (StringUtils.equals(rs.getRuleId(), k.get(rs.getRuleId()))) {
					continue;
				}
				RuleInfoListDto rl = new RuleInfoListDto();

				String ruleId = StringUtils.trimToEmpty(rs.getRuleId());
				rl.setDispFlag(dspflg);
				rl.setCheckFlag(checklist!=null&&checklist.contains(ruleId)?true:false);
				rl.setRuleId(ruleId);
				rl.setRuleName(rs.getRuleName());
				rl.setNote(rs.getNote());
				rl.setStartDate(rs.getStartDate());
				rl.setEndDate(rs.getEndDate());
				tolist.add(rl);
			}
		}
		return tolist;
	}

}


