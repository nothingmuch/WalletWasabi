using AvalonStudio.MVVM;
using ReactiveUI;
using System.Windows.Input;
using WalletWasabi.Gui.Validation;
using WalletWasabi.Models;
using WalletWasabi.Userfacing;

namespace WalletWasabi.Fluent.ViewModels
{
	public class SettingsPageViewModel : NavBarItemViewModel
	{
		private string _password;

		public SettingsPageViewModel(IScreen screen) : base(screen)
		{
			Title = "Settings";

			NextCommand = ReactiveCommand.Create(() => screen.Router.Navigate.Execute(new HomePageViewModel(screen)));

			this.ValidateProperty(x => x.Password, (IValidationErrors errors) => errors.Add(ErrorSeverity.Error, "Random Error Message"));
			this.OnPropertyChanged(nameof(Password));
		}

		public string Password
		{
			get => _password;
			set => this.RaiseAndSetIfChanged(ref _password, value);
		}

		public ICommand NextCommand { get; }

		public override string IconName => "settings_regular";
	}
}
