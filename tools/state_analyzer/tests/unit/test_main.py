from state_analyzer import main


class TestCanon(object):
    def test_base(self, mocker):
        mock_from_file = mocker.patch.object(main.yaml_util, 'from_file')
        mock_to_file = mocker.patch.object(main.yaml_util, 'to_file')

        main.canon('statefile', 'outfile')

        mock_from_file.assert_called_once_with('statefile')
        mock_to_file.assert_called_once_with(
            'outfile', mock_from_file.return_value
        )


class TestDot(object):
    def test_base(self, mocker):
        mock_from_file = mocker.patch.object(main.yaml_util, 'from_file')
        mock_to_file = mocker.patch.object(main.dot_util, 'to_file')

        main.dot('statefile', 'outfile')

        mock_from_file.assert_called_once_with('statefile')
        mock_to_file.assert_called_once_with(
            'outfile', mock_from_file.return_value
        )
