package jp.co.axio.masterMentsetSystem.repository;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import jp.co.axio.masterMentsetSystem.model.MgpCodeMst;
import jp.co.axio.masterMentsetSystem.model.MgpCodeMstExample;
import jp.co.axio.masterMentsetSystem.model.MgpCodeMstKey;

@Mapper
public interface MgpCodeMstMapper {
    long countByExample(MgpCodeMstExample example);

    int deleteByExample(MgpCodeMstExample example);

    int deleteByPrimaryKey(MgpCodeMstKey key);

    int insert(MgpCodeMst record);

    int insertSelective(MgpCodeMst record);

    List<MgpCodeMst> selectByExample(MgpCodeMstExample example);

    MgpCodeMst selectByPrimaryKey(MgpCodeMstKey key);

    int updateByExampleSelective(@Param("record") MgpCodeMst record, @Param("example") MgpCodeMstExample example);

    int updateByExample(@Param("record") MgpCodeMst record, @Param("example") MgpCodeMstExample example);

    int updateByPrimaryKeySelective(MgpCodeMst record);

    int updateByPrimaryKey(MgpCodeMst record);
}