package jp.co.axio.masterMentsetSystem.repository;

import java.util.List;
import jp.co.axio.masterMentsetSystem.model.OutputScopeMst;
import jp.co.axio.masterMentsetSystem.model.OutputScopeMstExample;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
@Mapper
public interface OutputScopeMstMapper {
    long countByExample(OutputScopeMstExample example);

    int deleteByExample(OutputScopeMstExample example);

    int insert(OutputScopeMst record);

    int insertSelective(OutputScopeMst record);

    List<OutputScopeMst> selectByExample(OutputScopeMstExample example);

    int updateByExampleSelective(@Param("record") OutputScopeMst record, @Param("example") OutputScopeMstExample example);

    int updateByExample(@Param("record") OutputScopeMst record, @Param("example") OutputScopeMstExample example);
}