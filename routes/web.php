<?php

use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Auth;
use App\Http\Controllers\CandidateController;
use App\Http\Controllers\SponsorshipController;
use App\Http\Controllers\CandidateRegistrationController;
use App\Http\Controllers\Auth\CustomLoginController;
use App\Http\Controllers\Auth\RegisterTypeController;
use App\Http\Controllers\VoterDashboardController;
use App\Http\Controllers\CandidateDashboardController;
use App\Http\Controllers\Admin\AdminDashboardController;
use App\Http\Controllers\Admin\AdminCandidateController;
use App\Http\Controllers\Admin\AdminSponsorshipController;
use App\Http\Controllers\Admin\VoterController;
use App\Http\Controllers\Admin\VoterImportController;
use App\Http\Controllers\Admin\VoterListController;
use App\Http\Controllers\Admin\StatisticsController;
use App\Http\Controllers\Admin\ReportController;
use App\Http\Controllers\Admin\AuditLogController;
use App\Http\Controllers\Admin\UserController;
use App\Http\Controllers\Admin\SettingController;
use App\Http\Controllers\TestMailController;
use App\Http\Controllers\Admin\SponsorshipPeriodController;
use App\Http\Middleware\AdminMiddleware;
use App\Http\Controllers\Admin\CandidateController as AdminCandidateReportController;
use App\Http\Controllers\ProfileController;

// Page d'accueil simple sans Vite
Route::get('/', function () {
    return view('welcome');
});

// Routes pour voir les différents designs
Route::get('/welcome1', function () {
    return view('welcome');
});

Route::get('/welcome2', function () {
    return view('welcome2');
});

Route::get('/welcome3', function () {
    return view('welcome3');
});

Route::get('/welcome-new', function () {
    return view('welcome_new');
});

Route::get('/welcome-simple', function () {
    return view('welcome_simple');
});

// Routes temporaires pour voir les différents designs
Route::get('/design1', function () {
    return view('welcome');
});

Route::get('/design2', function () {
    return view('welcome2');
});

Route::get('/design3', function () {
    return view('welcome3');
});

// Routes d'authentification
Route::middleware('guest')->group(function () {
    // Login routes
    Route::get('/login', [CustomLoginController::class, 'showLoginForm'])->name('login');
    Route::post('/login', [CustomLoginController::class, 'login']);
    
    // Routes d'inscription directes
    Route::get('/register/voter', [RegisterTypeController::class, 'showVoterForm'])->name('register.voter');
    Route::post('/register/voter', [RegisterTypeController::class, 'registerVoter'])->name('register.voter.submit');
    
    Route::get('/register/candidate', [RegisterTypeController::class, 'showCandidateForm'])->name('register.candidate');
    Route::post('/register/candidate', [RegisterTypeController::class, 'registerCandidate'])->name('register.candidate.submit');
});

Route::post('/logout', [CustomLoginController::class, 'logout'])->name('logout')->middleware('auth');

// Route de redirection après connexion
Route::get('/home', [App\Http\Controllers\HomeController::class, 'index'])->name('home');

// Routes pour la vérification
Route::get('/verify', function () {
    return view('auth.verify');
})->name('verification.notice');

Route::post('/verify', [\App\Http\Controllers\Auth\VerificationController::class, 'verify'])
    ->name('verification.verify');

// Routes de vérification d'email
Route::middleware(['auth'])->group(function () {
    Route::get('/verify', [App\Http\Controllers\Auth\EmailVerificationController::class, 'show'])
         ->name('verification.notice');
    Route::post('/verify', [App\Http\Controllers\Auth\EmailVerificationController::class, 'verify'])
         ->name('verification.verify');
    Route::get('/verify/resend', [App\Http\Controllers\Auth\EmailVerificationController::class, 'resend'])
         ->name('verification.resend');
});

// Routes de vérification des candidats
Route::middleware(['auth'])->group(function () {
    Route::get('/candidate-verify', [App\Http\Controllers\Auth\CandidateVerificationController::class, 'show'])
        ->name('candidate.verification.notice');
    Route::post('/candidate-verify', [App\Http\Controllers\Auth\CandidateVerificationController::class, 'verify'])
        ->name('candidate.verification.verify');
    Route::post('/candidate-verify/resend', [App\Http\Controllers\Auth\CandidateVerificationController::class, 'resend'])
        ->name('candidate.verification.resend');
});

// Routes protégées
Route::middleware(['web'])->group(function () {
    // Routes pour les électeurs
    Route::group([
        'prefix' => 'voter',
        'middleware' => ['auth', \App\Http\Middleware\VoterMiddleware::class]
    ], function () {
        Route::get('/dashboard', [VoterDashboardController::class, 'index'])->name('voter.dashboard');
        Route::get('/candidates', [VoterDashboardController::class, 'candidates'])->name('voter.candidates.index');
        Route::get('/candidates/{id}', [AdminCandidateController::class, 'voterShow'])->name('voter.candidates.show');
        
        // Routes pour les parrainages
        Route::get('/sponsorships/create/{candidate}', [SponsorshipController::class, 'create'])->name('voter.sponsorships.create');
        Route::post('/sponsorships/{candidate}', [SponsorshipController::class, 'store'])->name('voter.sponsorships.store');
        Route::get('/sponsorships', [SponsorshipController::class, 'index'])->name('voter.sponsorships.index');
        Route::get('/sponsorships/{id}', [SponsorshipController::class, 'show'])->name('voter.sponsorships.show');
        Route::post('/sponsor/{candidate}', [SponsorshipController::class, 'sponsor'])->name('voter.sponsor');
        
        // Gestion des parrainages
        Route::prefix('sponsorships')->name('sponsorships.')->group(function () {
            Route::get('/create/{candidate_id}', [SponsorshipController::class, 'create'])->name('create');
            Route::post('/store', [SponsorshipController::class, 'store'])->name('store');
        });

        // Routes du profil
        Route::get('/profile', [ProfileController::class, 'show'])->name('voter.profile');
        Route::put('/profile', [ProfileController::class, 'update'])->name('voter.profile.update');
    });

    // Routes pour les candidats
    Route::group([
        'prefix' => 'candidate',
        'middleware' => ['auth', 'verified']
    ], function () {
        Route::get('/dashboard', [CandidateDashboardController::class, 'index'])->name('candidate.dashboard');
        Route::get('/sponsorships', [CandidateDashboardController::class, 'sponsorships'])->name('candidate.sponsorships');
        Route::get('/profile', [CandidateDashboardController::class, 'profile'])->name('candidate.profile');
        Route::put('/profile', [CandidateDashboardController::class, 'updateProfile'])->name('candidate.profile.update');
        Route::get('/register', [CandidateRegistrationController::class, 'showRegistrationForm'])->name('candidate.register');
        Route::post('/register', [CandidateRegistrationController::class, 'register']);
        Route::get('/report/download', [CandidateDashboardController::class, 'downloadReport'])->name('candidate.report.download');
    });

    // Routes pour l'administration
    Route::prefix('admin')->middleware(['auth', \App\Http\Middleware\AdminMiddleware::class])->group(function () {
        // Redirection de /admin vers /admin/dashboard
        Route::get('/', function () {
            return redirect()->route('admin.dashboard');
        });

        // Dashboard admin
        Route::get('/dashboard', [AdminDashboardController::class, 'index'])->name('admin.dashboard');

        // Gestion des candidats
        Route::resource('candidates', AdminCandidateController::class)->names([
            'index' => 'admin.candidates.index',
            'create' => 'admin.candidates.create',
            'store' => 'admin.candidates.store',
            'show' => 'admin.candidates.show',
            'edit' => 'admin.candidates.edit',
            'update' => 'admin.candidates.update',
            'destroy' => 'admin.candidates.destroy'
        ]);
        Route::post('candidates/{candidate}/validate', [AdminCandidateController::class, 'validateCandidate'])
            ->name('admin.candidates.validate');
        Route::post('candidates/{candidate}/reject', [AdminCandidateController::class, 'reject'])
            ->name('admin.candidates.reject');
        Route::get('candidates/{id}/report', [AdminCandidateReportController::class, 'report'])
            ->name('admin.candidates.report');
        
        // Gestion des parrainages
        Route::get('/sponsorships', [AdminSponsorshipController::class, 'index'])->name('admin.sponsorships.index');
        Route::get('/sponsorships/{sponsorship}', [AdminSponsorshipController::class, 'show'])->name('admin.sponsorships.show');
        Route::put('/sponsorships/{sponsorship}/validate', [AdminSponsorshipController::class, 'validateSponsorship'])->name('admin.sponsorships.validate');
        Route::put('/sponsorships/{sponsorship}/reject', [AdminSponsorshipController::class, 'rejectSponsorship'])->name('admin.sponsorships.reject');
        
        // Gestion des électeurs
        Route::resource('voters', VoterController::class);
        
        // Import des électeurs
        Route::get('import-voters', [VoterImportController::class, 'showImportForm'])->name('admin.voters.import');
        Route::post('import-voters', [VoterImportController::class, 'import'])->name('admin.voters.import.submit');
        
        // Liste des électeurs
        Route::get('voter-list', [VoterListController::class, 'index'])->name('admin.voters.list');
        Route::get('voters/export', [VoterExportController::class, 'export'])->name('admin.voters.export');
        
        // Statistiques
        Route::get('statistics', [StatisticsController::class, 'index'])->name('admin.statistics');
        
        // Rapports
        Route::get('reports', [ReportController::class, 'index'])->name('admin.reports');
        
        // Journal d'audit
        Route::get('audit-log', [AuditLogController::class, 'index'])->name('admin.audit-log');
        
        // Gestion des utilisateurs
        Route::resource('users', UserController::class);
        
        // Paramètres
        Route::get('settings', [SettingController::class, 'index'])->name('admin.settings');
        Route::post('settings', [SettingController::class, 'update'])->name('admin.settings.update');
        
        // Gestion des périodes de parrainage
        Route::resource('sponsorship-periods', SponsorshipPeriodController::class)->names([
            'index' => 'admin.sponsorship-periods.index',
            'create' => 'admin.sponsorship-periods.create',
            'store' => 'admin.sponsorship-periods.store',
            'show' => 'admin.sponsorship-periods.show',
            'edit' => 'admin.sponsorship-periods.edit',
            'update' => 'admin.sponsorship-periods.update',
            'destroy' => 'admin.sponsorship-periods.destroy'
        ]);
    });
});

// Route de test pour l'email
Route::get('/test-mail', function () {
    \Illuminate\Support\Facades\Mail::raw('Test email from Laravel', function($message) {
        $message->to('diaoissa0290@gmail.com')
                ->subject('Test Email');
    });
    return 'Email de test envoyé !';
});

// Route de test détaillée pour l'email
Route::get('/test-mail-debug', function () {
    try {
        \Illuminate\Support\Facades\Mail::raw('Test email from Laravel with debug info', function($message) {
            $message->to('diaoissa0290@gmail.com')
                   ->subject('Test Email Debug');
        });
        return [
            'status' => 'success',
            'message' => 'Email envoyé avec succès',
            'mail_config' => [
                'driver' => config('mail.default'),
                'host' => config('mail.mailers.smtp.host'),
                'port' => config('mail.mailers.smtp.port'),
                'encryption' => config('mail.mailers.smtp.encryption'),
                'from_address' => config('mail.from.address'),
                'from_name' => config('mail.from.name'),
            ]
        ];
    } catch (\Exception $e) {
        return [
            'status' => 'error',
            'message' => $e->getMessage(),
            'trace' => $e->getTraceAsString()
        ];
    }
});

// Route de test email
Route::get('/test-email', [TestMailController::class, 'testMail'])
    ->name('test.mail');
