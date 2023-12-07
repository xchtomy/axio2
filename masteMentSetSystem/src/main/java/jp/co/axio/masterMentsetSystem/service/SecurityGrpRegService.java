package jp.co.axio.masterMentsetSystem.service;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Objects;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import jp.co.axio.masterMentsetSystem.common.LogService;
import jp.co.axio.masterMentsetSystem.controller.SecurityGrpBaseParam;
import jp.co.axio.masterMentsetSystem.controller.SecurityGrpRegForm;
import jp.co.axio.masterMentsetSystem.model.MGroupEntity;
import jp.co.axio.masterMentsetSystem.model.MOrganizationAdGroupEntity;
import jp.co.axio.masterMentsetSystem.repository.MGroupEntityMapper;
import jp.co.axio.masterMentsetSystem.repository.MOrganizationAdGroupMapper;
import jp.co.axio.masterMentsetSystem.repository.MOrganizationEntityMapper;
import jp.co.axio.masterMentsetSystem.repository.MgpCodeMstMapper;

@Service
public class SecurityGrpRegService {

    @Autowired
    MOrganizationEntityMapper mOrganizationEntityMapper;

    @Autowired
    MGroupEntityMapper mGroupEntityMapper;

    @Autowired
    MgpCodeMstMapper mgpCodeMstMapper;

    @Autowired
    MOrganizationAdGroupMapper mOrganizationAdGroupMapper;

    @Autowired
    SecurityGrpSetService securityGrpSetService;

    // 日付フォーマット
    SimpleDateFormat slashrFormat = new SimpleDateFormat("yyyy/MM/dd");

    // 画面名
    String SYSTEM_NAME = "組織セキュリティグループ登録";

    /** プロパティファイル グループID採番の頭綴り */
    @Value("${config.group.idPrefix}")
    private String idPrefix;

    /** プロパティファイル グループID採番の桁数 */
    @Value("${config.group.idNumLength:4}")
    private String idNumLength;

    @Autowired
    AuthGroupSetService authGroupSetService;

    /**
     * グループテーブル必須確認
     * 
     * @param securityGrpBaseParams
     * @return
     */
    public Boolean checkRequiredGroup(List<SecurityGrpBaseParam> tableParams) {

        Boolean ret = true;
        Boolean existFlag = false;

        // グループ名確認
        for (SecurityGrpBaseParam tableParam : tableParams) {

            // いずれかひとつ入力されているか確認
            // 存在する場合
            if (!StringUtils.isBlank(tableParam.getGroupName())) {
                existFlag = true;
            }
        }

        // 存在しない場合
        if (existFlag.equals(false)) {
            ret = false;
        }
        return ret;
    }

    /**
     * フォームの初期化
     * 
     * @param form
     * @return
     */
    public SecurityGrpRegForm resetValue(SecurityGrpRegForm form) {

        SecurityGrpRegForm newForm = new SecurityGrpRegForm();
        List<SecurityGrpBaseParam> securityGrpBaseParams = new ArrayList<>();
        List<MOrganizationAdGroupEntity> mOrganizationAdGroupEntities = new ArrayList<>();
        Calendar nowCal = Calendar.getInstance();

        newForm = form;

        // 表の初期値検索
        mOrganizationAdGroupEntities = mOrganizationAdGroupMapper.selectBaseParamInit();

        // 表の初期化
        for (MOrganizationAdGroupEntity e : mOrganizationAdGroupEntities) {

            SecurityGrpBaseParam sgbp = new SecurityGrpBaseParam();

            sgbp.setGroupType(e.getGroupType());
            sgbp.setGroupTypeName(e.getGroupTypeName());

            securityGrpBaseParams.add(sgbp);
        }

        newForm.setSelectSecurityGrpCode("");
        newForm.setSecurityGrpBaseList(securityGrpBaseParams);

        newForm.setStartDate(slashrFormat.format(nowCal.getTime()));
        newForm.setEndDate("2999/12/31");

        // その他
        newForm.setErrMessage("");

        return newForm;
    }

    /**
     * セキュリティグループIDからフォーム情報を取得
     * 
     * @param securityGroupCode
     * @param form
     * @return
     * @throws Exception
     */
    public SecurityGrpRegForm selectRegById(String securityGroupCode, SecurityGrpRegForm form) throws Exception {

        // セキュリティグループコード
        form.setSelectSecurityGrpCode(securityGroupCode);

        // SGマスタ取得
        List<MOrganizationAdGroupEntity> mOrganizationAdGroupEntities = new ArrayList<>();
        mOrganizationAdGroupEntities = securityGrpSetService.selectBaseParam(securityGroupCode);
        List<SecurityGrpBaseParam> securityGrpBaseList = new ArrayList<>();

        // 表取得
        for (MOrganizationAdGroupEntity e : mOrganizationAdGroupEntities) {

            SecurityGrpBaseParam sgbp = new SecurityGrpBaseParam();
            sgbp.setGroupType(e.getGroupType());
            sgbp.setGroupTypeName(e.getGroupTypeName());

            // 設定があるか確認
            if (!Objects.isNull(e.getGroupName())) {
                // 設定がある場合
                // 有効確認
                if (e.getInvalidFlag().equals("0")) {
                    // 有効な場合
                    sgbp.setGroupName(e.getGroupName());
                    sgbp.setGroupId(e.getGroupId());
                    sgbp.setNote(e.getNote());

                    // 設定がある場合
                    if (!Objects.isNull(e.getGroupName())) {
                        // 開始日
                        form.setStartDate(slashrFormat.format(e.getStartDate()));
                        // 終了日
                        form.setEndDate(slashrFormat.format(e.getEndDate()));
                    }

                } else {
                    // 無効な場合
                    sgbp.setGroupName("");
                    sgbp.setNote("");

                }
            }

            securityGrpBaseList.add(sgbp);

        }

        form.setSecurityGrpBaseList(securityGrpBaseList);

        return form;
    }

    /**
     * SGマスタ取得
     * 
     * @param form
     * @return
     */
    public List<MOrganizationAdGroupEntity> selectAdGroup(SecurityGrpRegForm form) {

        List<MOrganizationAdGroupEntity> entities = new ArrayList<>();

        entities = mOrganizationAdGroupMapper.selectAdGroup(form.getSelectSecurityGrpCode());

        return entities;
    }

    /**
     * SGマスタ挿入
     * 
     * @param form
     * @throws Exception
     */
    @Transactional
    public String insertAdGroup(SecurityGrpRegForm form) throws Exception {

        // セキュリティグループコード発行
        String securityGroupCode = mOrganizationAdGroupMapper.selectNewSecurityGroupCode();

        // 表の行数分ループ
        for (SecurityGrpBaseParam sgbp : form.getSecurityGrpBaseList()) {
            MOrganizationAdGroupEntity target = new MOrganizationAdGroupEntity();

            // フォームにグループ名がある場合
            if (!StringUtils.isBlank(sgbp.getGroupName())) {

                // グループマスタを検索
                target.setGroupId(
                        checkDuplicateAdGroup(form.getSelectSecurityGrpCode(), sgbp.getGroupName(), sgbp.getNote(),
                                form.getStartDate(), form.getEndDate(), ""));

                target.setSecurityGroupCode(securityGroupCode);
                target.setGroupType(sgbp.getGroupType());
                target.setGroupName(sgbp.getGroupName());
                target.setNote(sgbp.getNote());
                target.setStartDate(slashrFormat.parse(form.getStartDate()));
                target.setEndDate(slashrFormat.parse(form.getEndDate()));
                target.setInvalidFlag("0");

                // その他
                target.setRegisterId(SYSTEM_NAME);
                target.setUpdaterId(SYSTEM_NAME);

                // データ挿入
                mOrganizationAdGroupMapper.insertAdGroup(target);

                // 既存データを上書き
                updateDuplicatedAdGroup(target, target.getGroupId());

            } else {

                // 空のレコードを挿入
                target.setSecurityGroupCode(securityGroupCode);
                target.setGroupType(sgbp.getGroupType());
                target.setInvalidFlag("");

                // その他
                target.setRegisterId(SYSTEM_NAME);
                target.setUpdaterId(SYSTEM_NAME);

                mOrganizationAdGroupMapper.insertAdGroup(target);
            }

        }

        return securityGroupCode;

    }

    /**
     * SGマスタ更新
     * 
     * @param form
     * @param entities
     * @throws Exception
     */
    @Transactional
    public Integer updateAdGroup(SecurityGrpRegForm form) throws Exception {

        List<SecurityGrpBaseParam> sgbp = form.getSecurityGrpBaseList();
        List<MOrganizationAdGroupEntity> oldAdgroups = new ArrayList<>();
        oldAdgroups = securityGrpSetService.selectBaseParam(form.getSelectSecurityGrpCode());
        Integer ret = 0;

        // SGマスタ更新
        // SGマスタ挿入
        for (int i = 0; i < sgbp.size(); i++) {

            MOrganizationAdGroupEntity e = new MOrganizationAdGroupEntity();

            // 新規設定有無確認
            if (!sgbp.get(i).getGroupName().isBlank()) {
                // フォームに値が存在する場合
                // SGコード
                e.setSecurityGroupCode(form.getSelectSecurityGrpCode());
                // 開始日
                e.setStartDate(slashrFormat.parse(form.getStartDate()));
                // 終了日
                e.setEndDate(slashrFormat.parse(form.getEndDate()));
                // グループタイプ
                e.setGroupType(sgbp.get(i).getGroupType());
                // グループ名
                e.setGroupName(sgbp.get(i).getGroupName());
                // 備考
                e.setNote(sgbp.get(i).getNote());
                // 無効フラグ
                e.setInvalidFlag("0");
                // 登録者
                e.setRegisterId(SYSTEM_NAME);
                // 更新者
                e.setUpdaterId(SYSTEM_NAME);

                // グループID
                // 既存の設定有無確認
                if (!Objects.isNull(oldAdgroups.get(i).getGroupId())) {
                    // フォームに既存の設定有り
                    // 更新
                    e.setGroupId(checkDuplicateAdGroup(form.getSelectSecurityGrpCode(), sgbp.get(i).getGroupName(),
                            sgbp.get(i).getNote(), form.getStartDate(), form.getEndDate(), oldAdgroups.get(i).getGroupId()));

                    // 更新
                    mOrganizationAdGroupMapper.updateAdGroup(e);

                    // 既存データを上書き
                    updateDuplicatedAdGroup(e, oldAdgroups.get(i).getGroupId());

                } else {
                    // フォームに既存の設定無し
                    e.setGroupId(checkDuplicateAdGroup(form.getSelectSecurityGrpCode(), sgbp.get(i).getGroupName(),
                            sgbp.get(i).getNote(), form.getStartDate(), form.getEndDate(), ""));

                    // 既存にレコードがあるか確認
                    if (mOrganizationAdGroupMapper.countAdGroupRecord(form.getSelectSecurityGrpCode(),
                            sgbp.get(i).getGroupType()) != 0) {
                        // 存在する場合
                        // 更新
                        mOrganizationAdGroupMapper.updateAdGroup(e);

                        // 既存データを上書き
                        updateDuplicatedAdGroup(e, oldAdgroups.get(i).getGroupId());

                    } else {
                        // 存在しない場合
                        // 挿入
                        mOrganizationAdGroupMapper.insertAdGroup(e);

                        // 既存データを上書き
                        updateDuplicatedAdGroup(e, oldAdgroups.get(i).getGroupId());
                    }
                }

            } else {
                // 空の場合
                // 既存にグループIDが設定されていたか
                if (!sgbp.get(i).getGroupId().isBlank()) {
                    // グループIDがある場合
                    // 無効化
                    invalidAdGroup(form.getSelectSecurityGrpCode(), sgbp.get(i).getGroupType());
                } else {
                    // グループIDがなく、
                    // SGマスタに項目がない場合
                    if (mOrganizationAdGroupMapper.countAdGroupRecord(form.getSelectSecurityGrpCode(),
                            sgbp.get(i).getGroupType()) == 0) {

                        // 空のレコードを挿入
                        e.setSecurityGroupCode(form.getSelectSecurityGrpCode());
                        e.setGroupType(sgbp.get(i).getGroupType());
                        e.setInvalidFlag("");

                        // その他
                        e.setRegisterId(SYSTEM_NAME);
                        e.setUpdaterId(SYSTEM_NAME);

                        mOrganizationAdGroupMapper.insertAdGroup(e);
                    }

                }

            }
        }

        return ret;

    }

    /**
     * グループID取得
     * 変更先のグループ名と重複しているか検索
     * 
     * @param formGroupName
     * @param formNote
     * @return
     * @throws Exception
     */
    public String checkDuplicateAdGroup(String formSecurityGrpCode, String formGroupName, String formNote,
            String formStartDate, String formEndDate, String oldGroupId)
            throws Exception {

        // グループID
        String groupId;

        // 変更先と同じグループ名があった場合、グループIDを取得
        MGroupEntity mGroupEntity = new MGroupEntity();
        mGroupEntity = selectDuplicatedGroupName(formGroupName);

        // 重複確認
        if (!Objects.isNull(mGroupEntity)) {
            // 重複あり
            // 既存グループID取得
            groupId = mGroupEntity.getGroupId();

        } else {
            // 重複なし
            // 新規作成の場合
            if (oldGroupId.equals("")) {
                // グループID新規発行
                groupId = idPrefix + buriesZero(authGroupSetService.getNewId(), Integer.parseInt(idNumLength));
            } else {
                // 更新の場合
                groupId = oldGroupId;
            }
        }

        return groupId;
    }

    /**
     * 重複しているグループを上書き
     */
    public void updateDuplicatedAdGroup(MOrganizationAdGroupEntity newAdGroup, String oldGroupId) {

        // 変更前のグループが既存で重複しているか検索
        // 検索キーはグループID
        // 重複のあるセキュリティグループコードとラベル番号を取得
        List<MOrganizationAdGroupEntity> duplicatedGroups = new ArrayList<>();
        duplicatedGroups = mOrganizationAdGroupMapper.selectDuplicatedGroupId(
                newAdGroup.getSecurityGroupCode(), oldGroupId);

        // 重複処理
        if (duplicatedGroups.size() != 0) {
            // 重複しているグループを上書き
            mOrganizationAdGroupMapper.updateDuplicatedAdGroup(
                oldGroupId, newAdGroup.getGroupId(),
                newAdGroup.getGroupName(), newAdGroup.getNote()
            );

            mOrganizationAdGroupMapper.updateDateAdGroup(newAdGroup);

        }
    }

    /**
     * グループIDの後ろ番号の新規採番
     *
     * @return
     * @throws Exception
     */
    public String getNewId() throws Exception {
        LogService.info("グループ設定画面", "getNewId", "グループIDの後ろ番号の新規採番処理", "開始");

        MGroupEntity record = mGroupEntityMapper.getNewId();
        String newId = record.getGroupId();

        LogService.info("グループ設定画面", "getNewId", "グループIDの後ろ番号の新規採番処理", "正常終了");
        return newId;
    }

    /**
     * グループ名が重複しているレコードを取得
     * 
     * @param groupName
     * @return
     */
    public MGroupEntity selectDuplicatedGroupName(String groupName) {

        MGroupEntity mGroupEntity = new MGroupEntity();

        // グループマスタから同名のレコードを取得
        mGroupEntity = mOrganizationAdGroupMapper.selectDuplicatedGroupName(groupName);

        return mGroupEntity;

    }

    /**
     * SGマスタ無効化
     * 
     * @param securityGroupCode
     * @return
     */
    public Integer invalidAdGroup(String securityGroupCode) {

        MOrganizationAdGroupEntity entity = new MOrganizationAdGroupEntity();

        // 処理日前日を取得
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DATE, -1);

        // SGコード
        entity.setSecurityGroupCode(securityGroupCode);
        // 終了日
        entity.setEndDate(cal.getTime());
        // 無効フラグ
        entity.setInvalidFlag("1");
        // 更新者ID
        entity.setUpdaterId(SYSTEM_NAME);

        // 無効化
        Integer ret = mOrganizationAdGroupMapper.updateAdGroupInvalid(entity);

        return ret;

    }

    /**
     * セキュリティグループ単位で無効化する
     * 
     * @param securityGroupCode
     * @param groupId
     * @return
     */
    public Integer invalidAdGroup(String securityGroupCode, String groupType) {

        MOrganizationAdGroupEntity entity = new MOrganizationAdGroupEntity();

        // 処理日前日を取得
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DATE, -1);

        // SGコード
        entity.setSecurityGroupCode(securityGroupCode);
        // グループID
        entity.setGroupType(groupType);
        // 終了日
        entity.setEndDate(cal.getTime());
        // 無効フラグ
        entity.setInvalidFlag("1");
        // 更新者ID
        entity.setUpdaterId(SYSTEM_NAME);

        // 無効化
        Integer ret = mOrganizationAdGroupMapper.updateOneAdGroupInvalid(entity);

        return ret;

    }



    /**
     * グループ名の重複カウント
     */
    public Integer countAdGroupName(String groupName) {
        
        return mOrganizationAdGroupMapper.countAdGroupName(groupName);

    }

    /**
     * 引数に対して前0補完する（指定桁数分）
     *
     * @param str 変換対象文字列
     * @return String 0補完後の文字列
     */
    private String buriesZero(String str, int outStrLeng) {

        String inStr = "";
        if (str != null) {
            inStr = str;
        }
        String outStr = "";
        String outZeroStr = "";
        int inStrLeng = inStr.length();
        int buriesCnt = outStrLeng - inStrLeng;

        if (inStrLeng < outStrLeng) {
            for (int i = 0; i < buriesCnt; i++) {
                outZeroStr += "0";
            }
            outStr = outZeroStr + inStr;
        } else {
            outStr = inStr;
        }

        return outStr;
    }

}
