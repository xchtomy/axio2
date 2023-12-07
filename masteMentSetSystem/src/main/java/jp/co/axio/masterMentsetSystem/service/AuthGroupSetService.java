package jp.co.axio.masterMentsetSystem.service;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import jp.co.axio.masterMentsetSystem.common.LogService;
import jp.co.axio.masterMentsetSystem.dto.AuthGroupSetDto;
import jp.co.axio.masterMentsetSystem.model.MGroupEntity;
import jp.co.axio.masterMentsetSystem.model.MRuleEntity;
import jp.co.axio.masterMentsetSystem.repository.MGroupEntityMapper;
import jp.co.axio.masterMentsetSystem.repository.MRuleEntityMapper;
import jp.co.axio.masterMentsetSystem.util.StringUtil;

/**
 * グループ設定画面サービスクラス
 *
 * @author AXIO
 * @version 1.0
 */
@Service
public class AuthGroupSetService {


    @Autowired
    MRuleEntityMapper mRuleEntityMapper;

    @Autowired
    MGroupEntityMapper mGroupEntityMapper;

    /**
     * グループ関連ルールリスト取得
     *
     * @param groupId グループID
     * @return
     * @throws Exception
     */
    @Transactional
    public List<AuthGroupSetDto> selectGroupRuleList (String groupId) throws Exception{
        LogService.info("グループ設定画面", "selectGroupRuleList", "グループ関連ルールリスト検索処理", "開始");

        List<AuthGroupSetDto> groupRuleList = new ArrayList<>();
    	List<MRuleEntity> origList = mRuleEntityMapper.selectGroupRuleList(groupId);
    	for (MRuleEntity obj : origList) {
    		AuthGroupSetDto item = new AuthGroupSetDto();
    		item.setRuleId(obj.getRuleId());
    		item.setRuleName(obj.getRuleName());
    		item.setRuleNote(obj.getNote());
    		// 日付を文字列に変換
    		SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy/MM/dd");
    		SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy/MM/dd");
    		item.setRulePeriod(sdf1.format(obj.getStartDate()) + " - " + sdf2.format(obj.getEndDate()));

    		groupRuleList.add(item);
    	}

        LogService.info("グループ設定画面", "selectGroupRuleList", "グループ関連ルール検索処理", "正常終了");
    	return groupRuleList;
    }

    /**
     * グループIDの後ろ番号の新規採番
     *
     * @return
     * @throws Exception
     */
    @Transactional
    public String getNewId () throws Exception{
        LogService.info("グループ設定画面", "getNewId", "グループIDの後ろ番号の新規採番処理", "開始");

    	MGroupEntity record = mGroupEntityMapper.getNewId();
    	String newId = record.getGroupId();

        LogService.info("グループ設定画面", "getNewId", "グループIDの後ろ番号の新規採番処理", "正常終了");
    	return newId;
    }

    /**
     * グループ新規登録
     *
     * @param record グループ情報
     * @return
     * @throws Exception
     */
    @Transactional
    public int insertGroup (MGroupEntity record) throws Exception{
        LogService.info("グループ設定画面", "insertGroup", "グループ新規登録処理", "開始");

    	int cnt = mGroupEntityMapper.insert(record);

        LogService.info("グループ設定画面", "insertGroup", "グループ新規登録処理", "正常終了");
    	return cnt;
    }

    /**
     * グループ更新
     *
     * @param record グループ情報
     * @return
     * @throws Exception
     */
    @Transactional
    public int updateGroup (MGroupEntity record) throws Exception{
        LogService.info("グループ設定画面", "updateGroup", "グループ新規登録処理", "開始");

    	int cnt = mGroupEntityMapper.updateByInput(record);

        LogService.info("グループ設定画面", "updateGroup", "グループ新規登録処理", "正常終了");
    	return cnt;
    }

    /**
     * グループ重複チェック
     *
     * @param record グループ情報
     * @return
     * @throws Exception
     */
    @Transactional
    public boolean checkByGroupName (String groupName, String groupIdnow) throws Exception{
        LogService.info("グループ設定画面", "checkByGroupName", "グループ新規登録処理", "開始");

        boolean result = false;
        MGroupEntity data = mGroupEntityMapper.getValidByName(groupName);
        if (data != null && StringUtil.isNotBlank(data.getGroupId())) {
        	// 新規時、既存ありはNG
        	// 更新時、自分自身以外はNG
        	if (StringUtil.isBlank(groupIdnow) || (data.getGroupId().compareTo(groupIdnow) != 0)) {
            	result = true;
        	}
        }

        LogService.info("グループ設定画面", "checkByGroupName", "グループ新規登録処理", "正常終了");
    	return result;
    }

    /**
     * グループ削除（無効化）
     *
     * @param groupId グループID
     * @return
     * @throws Exception
     */
    @Transactional
    public int invalidGroup (String groupId) throws Exception{
        LogService.info("グループ設定画面", "invalidGroup", "グループ削除（無効）処理", "開始");

    	int cnt = mGroupEntityMapper.invalidByKey(groupId);

        LogService.info("グループ設定画面", "invalidGroup", "グループ削除（無効）処理", "正常終了");
    	return cnt;
    }

}
