package jp.co.axio.masterMentsetSystem.service;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Objects;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import jp.co.axio.masterMentsetSystem.common.LogService;
import jp.co.axio.masterMentsetSystem.controller.SecurityGrpBaseParam;
import jp.co.axio.masterMentsetSystem.controller.SecurityGrpSetForm;
import jp.co.axio.masterMentsetSystem.model.MGroupEntity;
import jp.co.axio.masterMentsetSystem.model.MOrganizationAdGroupEntity;
import jp.co.axio.masterMentsetSystem.model.MOrganizationEntity;
import jp.co.axio.masterMentsetSystem.model.MOrganizationEntityKey;
import jp.co.axio.masterMentsetSystem.model.ShMAdgroupEntity;
import jp.co.axio.masterMentsetSystem.model.VOrganizationADGroupEntity;
import jp.co.axio.masterMentsetSystem.repository.MGroupEntityMapper;
import jp.co.axio.masterMentsetSystem.repository.MOrganizationAdGroupMapper;
import jp.co.axio.masterMentsetSystem.repository.MOrganizationEntityMapper;
import jp.co.axio.masterMentsetSystem.repository.MgpCodeMstMapper;
import jp.co.axio.masterMentsetSystem.repository.ShMAdgroupEntityMapper;

/**
 * セキュリティグループ登録画面サービスクラス
 *
 * @author axio
 * @version 1.0
 */
@Service
public class SecurityGrpSetService {

    @Autowired
    MOrganizationEntityMapper mOrganizationEntityMapper;

    @Autowired
    MGroupEntityMapper mGroupEntityMapper;

    @Autowired
    ShMAdgroupEntityMapper shMAdgroupEntityMapper;

    @Autowired
    MgpCodeMstMapper mgpCodeMstMapper;

    @Autowired
    MOrganizationAdGroupMapper mOrganizationAdGroupMapper;

    // 日付フォーマット
    SimpleDateFormat slashrFormat = new SimpleDateFormat("yyyy/MM/dd");

    // 画面名
    String SYSTEM_NAME = "組織セキュリティグループ編集";

    /**
     * 組織情報確認
     * 
     * @param comanyCode
     * @param organizationCode
     * @return
     */
    public Boolean checkOrganizasion(String comanyCode, String organizationCode) {

        // 結果
        Boolean ret = true;

        // 必須項目チェック
        if (StringUtils.isBlank(comanyCode) || StringUtils.isBlank(organizationCode)) {
            ret = false;
        }

        return ret;
    }

    /**
     * 基本設定 表取得
     * 
     * @param form
     * @return
     * @throws Exception
     */
    @Transactional
    public List<MOrganizationAdGroupEntity> selectBaseParam(String securityGroupCode) throws Exception {
        LogService.info("セキュリティグループ登録画面", "selectSecurityGroup", "セキュリティグループ情報取得処理",
                "開始");

        List<MOrganizationAdGroupEntity> entity = new ArrayList<>();

        entity = mOrganizationAdGroupMapper.selectBaseParam(securityGroupCode);

        LogService.info("セキュリティグループ登録画面", "selectSecurityGroup", "セキュリティグループ情報取得処理",
                "正常終了");
        return entity;
    }

    /**
     * 設定関連取得
     * 表以外
     * 
     * @param form
     * @return
     * @throws Exception
     */
    @Transactional
    public MOrganizationAdGroupEntity selectBase(SecurityGrpSetForm form) throws Exception {

        LogService.info("セキュリティグループ登録画面", "selectSecurityGroup", "セキュリティグループ情報取得処理",
                "開始");

        MOrganizationAdGroupEntity entity = new MOrganizationAdGroupEntity();

        entity = mOrganizationAdGroupMapper.selectBase(form.getCompanyCode(), form.getOrganizationCode());

        LogService.info("セキュリティグループ登録画面", "selectSecurityGroup", "セキュリティグループ情報取得処理",
                "正常終了");
        return entity;

    }

    /**
     * 組織SGマスタ取得
     */
    @Transactional
    public MOrganizationAdGroupEntity selectOrganizationAdGroup(SecurityGrpSetForm form) {
        LogService.info("セキュリティグループ登録画面", "selectSecurityGroup", "セキュリティグループ情報取得処理",
                "開始");

        MOrganizationAdGroupEntity entity = new MOrganizationAdGroupEntity();

        entity = mOrganizationAdGroupMapper.selectOrganizationAdGroup(form.getCompanyCode(),
                form.getOrganizationCode());

        LogService.info("セキュリティグループ登録画面", "selectSecurityGroup", "セキュリティグループ情報取得処理",
                "正常終了");
        return entity;
    }

    /**
     * 組織SGマスタ登録
     * 
     * @param form
     * @return
     * @throws ParseException
     */
    @Transactional
    public Integer insertOrganizationAdGroup(SecurityGrpSetForm form) throws ParseException {

        MOrganizationAdGroupEntity e = new MOrganizationAdGroupEntity();

        // DTO
        // セキュリティグループコード新規取得
        e.setSecurityGroupCode(form.getSelectSecurityGrpCode());

        // 組織情報取得
        MOrganizationEntity organizationEntity = new MOrganizationEntity();
        MOrganizationEntityKey organizationKey = new MOrganizationEntityKey();
        organizationKey.setCompanyCode(form.getCompanyCode());
        organizationKey.setOrganizationCode(form.getOrganizationCode());
        organizationEntity = mOrganizationEntityMapper.selectByPrimaryKey(organizationKey);

        // 組織有無確認
        if (Objects.isNull(organizationEntity)) {
            // 存在しない場合
            // エラー
            return 0;
        } else {
            // 存在する場合
            e.setCompanyCode(organizationEntity.getCompanyCode());
            e.setOrganizationCode(organizationEntity.getOrganizationCode());
        }

        // 反映日
        if (form.getReflectionDate().isBlank()) {
            // NULL場合
            e.setReflectionDate(null);
        } else {
            // 値あり
            e.setReflectionDate(slashrFormat.parse(form.getReflectionDate()));

        }

        // 無効フラグ
        e.setInvalidFlag("0");

        /**
         * 詳細設定部分
         * アドオン領域
         * START
         */

        // 詳細設定1
        if (Objects.isNull(form.getOptionAttr1())) {
            e.setOptionAttr1("0");
        } else {
            e.setOptionAttr1(form.getOptionAttr1());
        }

        e.setOptionAttr2(form.getOptionAttr2());
        e.setOptionAttr3(form.getOptionAttr3());
        e.setOptionAttr4(form.getOptionAttr4());
        e.setOptionAttr5(form.getOptionAttr5());
        e.setOptionAttr6(form.getOptionAttr6());
        e.setOptionAttr7(form.getOptionAttr7());
        e.setOptionAttr8(form.getOptionAttr8());
        e.setOptionAttr9(form.getOptionAttr9());
        e.setOptionAttr10(form.getOptionAttr10());

        /**
         * 詳細設定部分
         * アドオン領域
         * END
         */

        // その他
        e.setRegisterId(SYSTEM_NAME);
        e.setUpdaterId(SYSTEM_NAME);

        Integer result = mOrganizationAdGroupMapper.insertOrganizationAdGroup(e);

        return result;

    }

    /**
     * 組織SGマスタ更新
     * 
     * @param form
     * @param entity
     * @return
     * @throws ParseException
     */
    @Transactional
    public Integer updateOrganizationAdGroup(SecurityGrpSetForm form, MOrganizationAdGroupEntity entity)
            throws ParseException {

        MOrganizationAdGroupEntity e = new MOrganizationAdGroupEntity();

        // 基本設定
        e.setSecurityGroupCode(form.getSelectSecurityGrpCode());
        e.setCompanyCode(form.getCompanyCode());
        e.setOrganizationCode(form.getOrganizationCode());
        e.setReflectionDate(slashrFormat.parse(form.getReflectionDate()));
        e.setInvalidFlag("0");

        /**
         * 詳細設定部分
         * アドオン領域
         * START
         */

        // 詳細設定1
        if (Objects.isNull(form.getOptionAttr1())) {
            e.setOptionAttr1("0");
        } else {
            e.setOptionAttr1(form.getOptionAttr1());
        }

        e.setOptionAttr2(form.getOptionAttr2());
        e.setOptionAttr3(form.getOptionAttr3());
        e.setOptionAttr4(form.getOptionAttr4());
        e.setOptionAttr5(form.getOptionAttr5());
        e.setOptionAttr6(form.getOptionAttr6());
        e.setOptionAttr7(form.getOptionAttr7());
        e.setOptionAttr8(form.getOptionAttr8());
        e.setOptionAttr9(form.getOptionAttr9());
        e.setOptionAttr10(form.getOptionAttr10());

        /**
         * 詳細設定部分
         * アドオン領域
         * END
         */

        // その他
        e.setUpdaterId(SYSTEM_NAME);

        Integer result = mOrganizationAdGroupMapper.updateOrganizationAdGroup(e);

        return result;
    }

    /**
     * 設定済みセキュリティグループ取得
     * 
     * @return
     * @throws ParseException
     */
    @Transactional
    public List<SecurityGrpBaseParam> selectSetting() throws ParseException {

        List<SecurityGrpBaseParam> returnList = new ArrayList<>();
        List<MOrganizationAdGroupEntity> entityList = new ArrayList<>();

        entityList = mOrganizationAdGroupMapper.selectSetting();

        // NULL⇒空文字変換
        for (MOrganizationAdGroupEntity entity : entityList) {
            returnList.add(setForm(entity));
        }

        return returnList;

    }

    /**
     * 未設定セキュリティグループ取得
     * 
     * @return
     * @throws ParseException
     */
    @Transactional
    public List<SecurityGrpBaseParam> selectNotSetting() throws ParseException {

        List<SecurityGrpBaseParam> returnList = new ArrayList<>();
        List<MOrganizationAdGroupEntity> entityList = new ArrayList<>();

        entityList = mOrganizationAdGroupMapper.selectNotSetting();

        // NULL⇒空文字変換
        for (MOrganizationAdGroupEntity entity : entityList) {
            returnList.add(setForm(entity));
        }

        return returnList;

    }

    /**
     * グループIDの新規採番（GRP-xxxx）
     *
     * @return newId 新規採番したグループID
     * @throws Exception
     */
    @Transactional
    public String getNewId() throws Exception {
        LogService.info("セキュリティグループ登録画面", "getNewId", "グループID新規採番処理", "開始");
        MGroupEntity record = mGroupEntityMapper.getNewId();
        String newId = record.getGroupId();
        LogService.info("セキュリティグループ登録画面", "getNewId", "グループID新規採番処理", "正常終了");
        return newId;
    }

    /**
     * グループIDの取得
     *
     * @return groupId グループID
     * @throws Exception
     */
    @Transactional
    public String getByGroupNameJp(String groupNameJp) throws Exception {
        LogService.info("セキュリティグループ登録画面", "getByGroupNameJp", "グループID取得処理", "開始");
        MGroupEntity record = mGroupEntityMapper.getByGroupNameJp(groupNameJp);
        String groupId = "";
        if (record != null) {
            groupId = record.getGroupId();
        }
        LogService.info("セキュリティグループ登録画面", "getByGroupNameJp", "グループID取得処理", "正常終了");
        return groupId;
    }

    /**
     * セキュリティグループ情報更新
     *
     * @param record セキュリティグループ情報
     * @return 更新件数
     * @throws Exception
     */
    @Transactional
    public int updateSecurityGroup(ShMAdgroupEntity entity) throws Exception {
        LogService.info("セキュリティグループ登録画面", "updateSecurityGroup", "セキュリティグループ情報更新処理", "開始");

        int cnt = shMAdgroupEntityMapper.update(entity);

        LogService.info("セキュリティグループ登録画面", "updateSecurityGroup", "セキュリティグループ情報更新処理", "正常終了");
        return cnt;
    }

    /**
     * 組織SG取得
     */
    @Transactional
    public List<VOrganizationADGroupEntity> selectSecurityGroup(String securityGroupId) {

        List<VOrganizationADGroupEntity> orgAdGroupList = new ArrayList<>();

        // orgAdGroupList = mOrganizationAdGroupMapper.select("sgid", "date");

        return orgAdGroupList;
    }

    /**
     * 組織SGのFORMに設定
     * 
     * @param form
     * @param entityList
     * @return
     * @throws Exception
     */
    public SecurityGrpSetForm setForm(SecurityGrpSetForm form, List<MOrganizationAdGroupEntity> entityList)
            throws Exception {

        List<SecurityGrpBaseParam> securityGrpBaseList = new ArrayList<>();
        MOrganizationAdGroupEntity ogEntity = new MOrganizationAdGroupEntity();

        // 組織SGマスタ設定情報取得
        ogEntity = this.selectBase(form);

        // 組織設定有無確認
        if (Objects.isNull(ogEntity)) {
            // 設定がない場合
            Calendar nowCal = Calendar.getInstance();

            form.setCompanyCode("");
            form.setOrganizationCode("");
            form.setOrganizationName("");
            form.setSelectSecurityGrpCode(form.getSelectSecurityGrpCode());
            form.setReflectionDate(slashrFormat.format(nowCal.getTime()));
            
            // 詳細設定
            form.setOptionAttr1("");
            form.setOptionAttr2("");
            form.setOptionAttr3("");
            form.setOptionAttr4("");
            form.setOptionAttr5("");
            form.setOptionAttr6("");
            form.setOptionAttr7("");
            form.setOptionAttr8("");
            form.setOptionAttr9("");
            form.setOptionAttr10("");

        } else {
            // 設定がある場合
            // 基本設定(表以外)
            form.setCompanyCode(ogEntity.getCompanyCode());
            form.setOrganizationCode(ogEntity.getOrganizationCode());
            form.setOrganizationName(ogEntity.getOrganizationName());
            form.setSelectSecurityGrpCode(ogEntity.getSecurityGroupCode());

            // 日付確認
            if (Objects.isNull(ogEntity.getReflectionDate())) {
                // 反映日が空
                // 何もしない
            } else {
                // 反映日が存在
                // 日付変換
                form.setReflectionDate(slashrFormat.format(ogEntity.getReflectionDate()));

            }

            // 詳細設定
            form.setOptionAttr1(ogEntity.getOptionAttr1());
            form.setOptionAttr2(ogEntity.getOptionAttr2());
            form.setOptionAttr3(ogEntity.getOptionAttr3());
            form.setOptionAttr4(ogEntity.getOptionAttr4());
            form.setOptionAttr5(ogEntity.getOptionAttr5());
            form.setOptionAttr6(ogEntity.getOptionAttr6());
            form.setOptionAttr7(ogEntity.getOptionAttr7());
            form.setOptionAttr8(ogEntity.getOptionAttr8());
            form.setOptionAttr9(ogEntity.getOptionAttr9());
            form.setOptionAttr10(ogEntity.getOptionAttr10());
        }

        // 基本設定の表設定
        for (MOrganizationAdGroupEntity entity : entityList) {

            SecurityGrpBaseParam securityGrpBase = new SecurityGrpBaseParam();

            // グループタイプ
            securityGrpBase.setGroupType(entity.getGroupType());
            // グループタイプ名
            securityGrpBase.setGroupTypeName(entity.getGroupTypeName());

            // 設定があるか確認
            if (!Objects.isNull(entity.getGroupName())) {
                // 有効か確認
                if (entity.getInvalidFlag().equals("0")) {
                    // 有効な場合
                    // グループ名
                    securityGrpBase.setGroupName(entity.getGroupName());
                    // 備考
                    securityGrpBase.setNote(entity.getNote());
                    // 開始日
                    // 日付確認
                    if (Objects.isNull(entity.getStartDate())) {
                        // 開始日が空
                        // 何もしない
                    } else {
                        // 開始日が存在
                        // 日付変換
                        securityGrpBase.setStartDate(slashrFormat.format(entity.getStartDate()));

                    }
                    // 終了日
                    // 日付確認
                    if (Objects.isNull(entity.getStartDate())) {
                        // 終了日が空
                        // 何もしない
                    } else {
                        // 終了日が存在
                        // 日付変換
                        securityGrpBase.setEndDate(slashrFormat.format(entity.getEndDate()));

                    }

                } else {
                    // 無効な場合
                    // グループ名
                    securityGrpBase.setGroupName("");
                    // 備考
                    securityGrpBase.setNote("");
                    // 開始日
                    securityGrpBase.setStartDate("");
                    // 終了日
                    securityGrpBase.setEndDate("");
                }
            }

            securityGrpBaseList.add(securityGrpBase);

        }

        form.setSecurityGrpBaseList(securityGrpBaseList);

        // その他
        form.setErrMessage("");

        return form;
    }

    /**
     * NULL⇒空文字変換
     * 
     * @param entity
     * @return
     * @throws ParseException
     */
    public SecurityGrpBaseParam setForm(MOrganizationAdGroupEntity entity) throws ParseException {

        SecurityGrpBaseParam e = new SecurityGrpBaseParam();

        // セキュリティグループコード
        if (Objects.isNull(entity.getSecurityGroupCode())) {
            e.setSecurityGroupCode("");
        } else {
            e.setSecurityGroupCode(entity.getSecurityGroupCode());
        }

        // 会社コード
        if (Objects.isNull(entity.getCompanyCode())) {
            e.setCompanyCode("");
        } else {
            e.setCompanyCode(entity.getCompanyCode());
        }

        // 組織コード
        if (Objects.isNull(entity.getOrganizationCode())) {
            e.setOrganizationCode("");
        } else {
            e.setOrganizationCode(entity.getOrganizationCode());
        }

        // 組織名
        if (Objects.isNull(entity.getOrganizationName())) {
            e.setOrganizationName("");
        } else {
            e.setOrganizationName(entity.getOrganizationName());
        }

        // グループ名
        if (Objects.isNull(entity.getGroupName())) {
            e.setGroupName("");
        } else {
            e.setGroupName(entity.getGroupName());
        }

        // グループタイプ
        if (Objects.isNull(entity.getGroupType())) {
            e.setGroupType("");
        } else {
            e.setGroupType(entity.getGroupType());
        }

        // グループタイプ名
        if (Objects.isNull(entity.getGroupTypeName())) {
            e.setGroupTypeName("");
        } else {
            e.setGroupTypeName(entity.getGroupTypeName());
        }

        // 備考
        if (Objects.isNull(entity.getNote())) {
            e.setNote("");
        } else {
            e.setNote(entity.getNote());
        }

        // 開始日
        if (Objects.isNull(entity.getStartDate())) {
            e.setStartDate("");
        } else {
            e.setStartDate(slashrFormat.format(entity.getStartDate()));
        }

        // 終了日
        if (Objects.isNull(entity.getEndDate())) {
            e.setEndDate("");
        } else {
            e.setEndDate(slashrFormat.format(entity.getEndDate()));
        }

        // 反映日
        if (Objects.isNull(entity.getReflectionDate())) {
            e.setReflectionDate("");
        } else {
            e.setReflectionDate(slashrFormat.format(entity.getReflectionDate()));
        }

        return e;
    }

    /**
     * フォーム情報初期化
     *
     * @param form フォーム情報
     */
    public SecurityGrpSetForm resetValue(SecurityGrpSetForm form) {

        // 表の初期値の取得
        List<MOrganizationAdGroupEntity> securityGroupBaseLista = new ArrayList<>();
        securityGroupBaseLista = mOrganizationAdGroupMapper.selectBaseParamInit();

        // form設定変数
        List<SecurityGrpBaseParam> securityGroupBaseList = new ArrayList<>();

        // 値設定
        for (MOrganizationAdGroupEntity e : securityGroupBaseLista) {

            SecurityGrpBaseParam securityGroupBaseParam = new SecurityGrpBaseParam();

            // グループタイプ
            securityGroupBaseParam.setGroupType(e.getGroupType());
            // グループタイプ名
            securityGroupBaseParam.setGroupTypeName(e.getGroupTypeName());

            securityGroupBaseList.add(securityGroupBaseParam);
        }

        // 会社コード
        form.setCompanyCode("");
        // 組織コード
        form.setOrganizationCode("");
        // 組織名
        form.setOrganizationName("");
        // 初期の表
        form.setSecurityGrpBaseList(securityGroupBaseList);
        // 反映日
        form.setReflectionDate("");
        // 組織セキュリティグループコード
        form.setSelectSecurityGrpCode("");

        return form;

    }

    /**
     * 紐づき解除
     * @param form
     * @return
     */
    public Integer clear(MOrganizationAdGroupEntity entity) {

        // クリア
        entity.setUpdaterId(SYSTEM_NAME);
        entity.setInvalidFlag("1");
        Integer result = mOrganizationAdGroupMapper.updateOrganizationAdGroup(entity);
        
        return result;
    }

    /**
     * 項目確認
     * 
     * @param form
     * @return
     */
    public Boolean checkFormValues(SecurityGrpSetForm form) {

        Boolean ret = true;

        // セキュリティグループコード確認
        if (form.getSelectSecurityGrpCode().isBlank()) {
            ret = false;
        }

        // 組織コード確認
        if (form.getOrganizationCode().isBlank()) {
            ret = false;
        }

        // 反映日
        if (form.getReflectionDate().isBlank()) {
            ret = false;
        }

        return ret;

    }

    /**
     * 選択組織重複確認
     * 
     * @param form
     * @return
     */
    @Transactional
    public Boolean checkDuplicatedOrganization(SecurityGrpSetForm form) {

        // 結果
        Boolean ret;

        // 既に選択した組織を設定しているか確認
        Integer cnt = mOrganizationAdGroupMapper.countAdGroupOrg(form.getCompanyCode(), form.getOrganizationCode());

        if (cnt == 0) {
            // 重複なし
            ret = false;
        } else {
            // 重複あり
            ret = true;
        }

        return ret;

    }

}